package promlabel

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/proxy"
)

type staticSource struct{ cfg *config.Config }

func (s staticSource) Current() *config.Config { return s.cfg }

// received is what the backend actually got.
type received struct {
	method, path, rawQuery, contentType, body string
	acceptEncoding                            string
	form                                      url.Values
}

// env is the production chain: Handler, the real reverse proxy and transport,
// and a backend recording what reached it.
type env struct {
	handler  http.Handler
	mu       sync.Mutex
	requests []received
	respond  func(w http.ResponseWriter, r *http.Request)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// What a backend using FormValue sees, multipart included.
		parsed := r.Clone(r.Context())
		parsed.Body = io.NopCloser(bytes.NewReader(body))
		_ = parsed.ParseMultipartForm(1 << 20)
		e.mu.Lock()
		e.requests = append(e.requests, received{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			contentType: r.Header.Get("Content-Type"), body: string(body),
			acceptEncoding: r.Header.Get("Accept-Encoding"), form: parsed.Form,
		})
		e.mu.Unlock()
		if e.respond != nil {
			e.respond(w, r)
		}
	}))
	t.Cleanup(backend.Close)

	cfg := &config.Config{ListenAddr: ":0", Target: backend.URL}
	require.NoError(t, cfg.Validate())
	source := staticSource{cfg}
	transport := proxy.BuildTransport(cfg)
	rp := proxy.New(source, slog.New(slog.DiscardHandler), transport)
	rp.ModifyResponse = ModifyResponse
	e.handler = New(source, rp, transport, slog.New(slog.DiscardHandler))
	return e
}

func (e *env) last(t *testing.T) received {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotEmpty(t, e.requests, "nothing reached the backend")
	return e.requests[len(e.requests)-1]
}

func (e *env) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.requests)
}

func (e *env) serve(r *http.Request, s Scope) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, r.WithContext(WithScope(r.Context(), s)))
	return rec
}

func tenantA() []Label { return []Label{{Name: "namespace", Values: []string{"a"}}} }

func scoped(t *testing.T, method, path string, ls []Label, prefixes ...string) Scope {
	t.Helper()
	if len(prefixes) == 0 {
		prefixes = []string{""}
	}
	endpoint, prefix, ok := Route(prefixes, method, path)
	require.True(t, ok, "%s %s is not routed", method, path)
	return Scope{Labels: ls, Endpoint: endpoint, Prefix: prefix}
}

func get(t *testing.T, target string) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
}

func postForm(t *testing.T, target string, v url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", formContentType)
	return r
}

func queryOf(t *testing.T, rawQuery string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(rawQuery)
	require.NoError(t, err)
	return v
}

func TestRoute(t *testing.T) {
	prefixes := []string{"/prometheus/deep", "/prometheus", "/api/prom"}
	tests := []struct {
		method, path string
		want         Endpoint
		wantPrefix   string
	}{
		{"GET", "/prometheus/api/v1/query", endpointQuery, "/prometheus"},
		{"POST", "/api/prom/api/v1/query_range", endpointQuery, "/api/prom"},
		{"GET", "/prometheus/deep/api/v1/series", endpointMatch, "/prometheus/deep"},
		{"GET", "/prometheus/api/v1/label/job/values", endpointMatch, "/prometheus"},
		{"GET", "/prometheus/api/v1/rules", endpointRules, "/prometheus"},
		{"GET", "/prometheus/api/v2/silences", endpointSilences, "/prometheus"},
		{"DELETE", "/prometheus/api/v2/silence/abc", endpointSilenceID, "/prometheus"},
		{"GET", "/prometheus/federate", endpointMatch, "/prometheus"},
	}
	for _, tt := range tests {
		got, prefix, ok := Route(prefixes, tt.method, tt.path)
		assert.True(t, ok, tt.path)
		assert.Equal(t, tt.want, got, tt.path)
		assert.Equal(t, tt.wantPrefix, prefix, tt.path)
	}

	denied := []struct{ method, path string }{
		{"GET", "/api/v1/query"},                           // outside every prefix
		{"GET", "/prometheusx/api/v1/query"},               // not a segment boundary
		{"GET", "/prometheus/api/v1/read"},                 // unenforced
		{"POST", "/prometheus/api/v1/read"},                //
		{"GET", "/prometheus/api/v1/query/"},               // not the endpoint
		{"PUT", "/prometheus/api/v1/query"},                // wrong method
		{"POST", "/prometheus/api/v1/rules"},               //
		{"DELETE", "/prometheus/api/v2/silences"},          //
		{"GET", "/prometheus/api/v2/silence/abc"},          //
		{"POST", "/prometheus/api/v2/alerts"},              // would inject alerts
		{"GET", "/prometheus/api/v1/label//values"},        //
		{"GET", "/prometheus/api/v1/label/a/b/values"},     //
		{"GET", "/prometheus/deep/prometheus/api/v1/read"}, //
	}
	for _, tt := range denied {
		_, _, ok := Route(prefixes, tt.method, tt.path)
		assert.False(t, ok, "%s %s", tt.method, tt.path)
	}

	// "/federate" starts with "/fed" but is not under it.
	got, prefix, ok := Route([]string{"/fed", ""}, "GET", "/federate")
	assert.True(t, ok)
	assert.Equal(t, endpointMatch, got)
	assert.Empty(t, prefix)
}

func TestQuery_Injected(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"selector", `up`, `up{namespace="a"}`},
		{"or", `up or other`, `up{namespace="a"} or other{namespace="a"}`},
		{"subquery", `max_over_time(up[5m:1m])`, `max_over_time(up{namespace="a"}[5m:1m])`},
		{"aggregation", `sum by (job) (rate(x[5m]))`, `sum by (job) (rate(x{namespace="a"}[5m]))`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			r := get(t, "/api/v1/query?"+url.Values{"query": {tt.in}, "time": {"1"}}.Encode())
			rec := e.serve(r, scoped(t, "GET", "/api/v1/query", tenantA()))
			require.Equal(t, http.StatusOK, rec.Code)
			got := queryOf(t, e.last(t).rawQuery)
			assert.Equal(t, tt.want, got.Get("query"))
			assert.Equal(t, "1", got.Get("time"))
		})
	}
}

func TestQuery_PostBody(t *testing.T) {
	e := newEnv(t)
	r := postForm(t, "/api/v1/query", url.Values{"query": {"up"}})
	rec := e.serve(r, scoped(t, "POST", "/api/v1/query", tenantA()))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `up{namespace="a"}`, queryOf(t, e.last(t).body).Get("query"))
	assert.Equal(t, formContentType, e.last(t).contentType)
}

func TestQuery_PostBodyAndURLBothEnforced(t *testing.T) {
	e := newEnv(t)
	r := postForm(t, "/api/v1/query?query=evil", url.Values{"query": {"up"}})
	rec := e.serve(r, scoped(t, "POST", "/api/v1/query", tenantA()))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `evil{namespace="a"}`, queryOf(t, e.last(t).rawQuery).Get("query"))
	assert.Equal(t, `up{namespace="a"}`, queryOf(t, e.last(t).body).Get("query"))
}

func TestQuery_SeveralLabelsAndValues(t *testing.T) {
	e := newEnv(t)
	ls := []Label{{Name: "namespace", Values: []string{"a.b", "c|d"}}, {Name: "cluster", Values: []string{"x"}}}
	r := get(t, "/api/v1/query?query=up")
	e.serve(r, scoped(t, "GET", "/api/v1/query", ls))
	q := queryOf(t, e.last(t).rawQuery).Get("query")
	assert.Contains(t, q, `namespace=~"a\\.b|c\\|d"`, "values must be escaped")
	assert.Contains(t, q, `cluster="x"`)
}

func TestQuery_CallerMatcher(t *testing.T) {
	tests := []struct {
		name, query string
		ls          []Label
		status      int
		want        string
	}{
		{"disjoint", `up{namespace="b"}`, tenantA(), 400, ""},
		{"disjoint regex", `up{namespace=~"b.*"}`, tenantA(), 400, ""},
		{"same", `up{namespace="a"}`, tenantA(), 200, `up{namespace="a"}`},
		{"disjoint in a second selector", `up{namespace="a"} or up{namespace="b"}`, tenantA(), 400, ""},
		{"disjoint with several values", `up{namespace="c"}`, []Label{{Name: "namespace", Values: []string{"a", "b"}}}, 400, ""},
		{"narrowing with several values", `up{namespace="b"}`, []Label{{Name: "namespace", Values: []string{"a", "b"}}}, 200, `up{namespace="b",namespace=~"a|b"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			r := get(t, "/api/v1/query?"+url.Values{"query": {tt.query}}.Encode())
			rec := e.serve(r, scoped(t, "GET", "/api/v1/query", tt.ls))
			assert.Equal(t, tt.status, rec.Code, rec.Body.String())
			if tt.status != 200 {
				assert.Zero(t, e.count(), "must not reach the backend")
				return
			}
			assert.Equal(t, tt.want, queryOf(t, e.last(t).rawQuery).Get("query"))
		})
	}
}

func TestQuery_Refused(t *testing.T) {
	tests := []struct {
		name   string
		build  func(t *testing.T) *http.Request
		status int
	}{
		{"no query", func(t *testing.T) *http.Request { return get(t, "/api/v1/query") }, 400},
		{"unparsable", func(t *testing.T) *http.Request { return get(t, "/api/v1/query?query=%7B") }, 400},
		{"empty then real", func(t *testing.T) *http.Request { return get(t, "/api/v1/query?query=&query=evil") }, 400},
		{"two queries", func(t *testing.T) *http.Request { return get(t, "/api/v1/query?query=a&query=evil") }, 400},
		{"semicolon", func(t *testing.T) *http.Request { return get(t, "/api/v1/query?query=a;query=evil") }, 400},
		{"multipart post", func(t *testing.T) *http.Request {
			return multipartRequest(t, http.MethodPost, "/api/v1/query")
		}, 415},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			r := tt.build(t)
			rec := e.serve(r, scoped(t, r.Method, "/api/v1/query", tenantA()))
			assert.Equal(t, tt.status, rec.Code)
			assert.Zero(t, e.count(), "must not reach the backend")
		})
	}
}

func multipartRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.WriteField("query", "evil"))
	require.NoError(t, mw.Close())
	r := httptest.NewRequestWithContext(t.Context(), method, target, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// A backend reading parameters with FormValue parses a multipart body on any
// method, and body values win over the URL. The body must not survive.
func TestQuery_GetBodyDoesNotReachBackend(t *testing.T) {
	e := newEnv(t)
	r := multipartRequest(t, http.MethodGet, "/api/v1/query?query=up")
	rec := e.serve(r, scoped(t, "GET", "/api/v1/query", tenantA()))
	require.Equal(t, http.StatusOK, rec.Code)
	got := e.last(t)
	assert.Empty(t, got.body)
	assert.Equal(t, []string{`up{namespace="a"}`}, got.form["query"])
}

func TestMatch(t *testing.T) {
	t.Run("each selector enforced", func(t *testing.T) {
		e := newEnv(t)
		r := get(t, "/api/v1/series?"+url.Values{"match[]": {"up", `x{job="y"}`}}.Encode())
		e.serve(r, scoped(t, "GET", "/api/v1/series", tenantA()))
		assert.Equal(t, []string{`up{namespace="a"}`, `x{job="y",namespace="a"}`}, queryOf(t, e.last(t).rawQuery)["match[]"])
	})
	t.Run("added when there is none", func(t *testing.T) {
		e := newEnv(t)
		e.serve(get(t, "/api/v1/labels"), scoped(t, "GET", "/api/v1/labels", tenantA()))
		assert.Equal(t, []string{`{namespace="a"}`}, queryOf(t, e.last(t).rawQuery)["match[]"])
	})
	t.Run("label values", func(t *testing.T) {
		e := newEnv(t)
		e.serve(get(t, "/api/v1/label/job/values"), scoped(t, "GET", "/api/v1/label/job/values", tenantA()))
		assert.Equal(t, []string{`{namespace="a"}`}, queryOf(t, e.last(t).rawQuery)["match[]"])
	})
	t.Run("post body, no extra URL selector", func(t *testing.T) {
		e := newEnv(t)
		r := postForm(t, "/api/v1/series", url.Values{"match[]": {"up"}})
		e.serve(r, scoped(t, "POST", "/api/v1/series", tenantA()))
		got := e.last(t)
		assert.Equal(t, []string{`up{namespace="a"}`}, got.form["match[]"])
	})
	t.Run("body selector can't dodge a URL one", func(t *testing.T) {
		e := newEnv(t)
		r := postForm(t, "/api/v1/series?"+url.Values{"match[]": {"a"}}.Encode(), url.Values{"match[]": {"b"}})
		e.serve(r, scoped(t, "POST", "/api/v1/series", tenantA()))
		assert.ElementsMatch(t, []string{`a{namespace="a"}`, `b{namespace="a"}`}, e.last(t).form["match[]"])
	})
	t.Run("disjoint selector refused", func(t *testing.T) {
		e := newEnv(t)
		r := get(t, "/api/v1/series?"+url.Values{"match[]": {`up{namespace="b"}`}}.Encode())
		rec := e.serve(r, scoped(t, "GET", "/api/v1/series", tenantA()))
		assert.Equal(t, 400, rec.Code)
		assert.Zero(t, e.count())
	})
}

func TestHandler_PrefixForwardedUnchanged(t *testing.T) {
	e := newEnv(t)
	r := get(t, "/prometheus/api/v1/query?query=up")
	e.serve(r, scoped(t, "GET", "/prometheus/api/v1/query", tenantA(), "/prometheus"))
	assert.Equal(t, "/prometheus/api/v1/query", e.last(t).path)
}

func TestHandler_Bypass(t *testing.T) {
	e := newEnv(t)
	r := get(t, "/anything?query=up")
	rec := e.serve(r, Scope{Bypass: true})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "query=up", e.last(t).rawQuery)
}

func TestHandler_NoVerdict(t *testing.T) {
	block := &config.PromLabelProxyConfig{}
	cfg := &config.Config{Outbound: config.OutboundConfig{PromLabelProxy: block}}
	called := false
	h := New(staticSource{cfg}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), nil, slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, get(t, "/api/v1/query?query=up"))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, called)

	cfg = &config.Config{}
	h = New(staticSource{cfg}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), nil, slog.New(slog.DiscardHandler))
	h.ServeHTTP(httptest.NewRecorder(), get(t, "/x"))
	assert.True(t, called, "without the block, requests forward as ever")
}

func TestAMFilter(t *testing.T) {
	e := newEnv(t)
	ls := []Label{{Name: "namespace", Values: []string{"a", "b"}}}
	r := get(t, "/api/v2/alerts?"+url.Values{"filter": {`namespace="c"`}, "active": {"true"}}.Encode())
	e.serve(r, scoped(t, "GET", "/api/v2/alerts", ls))
	got := queryOf(t, e.last(t).rawQuery)
	assert.ElementsMatch(t, []string{`namespace="c"`, `namespace=~"a|b"`}, got["filter"], "ANDed, so the caller can only narrow")
	assert.Equal(t, "true", got.Get("active"))
}

const rulesBody = `{"status":"success","data":{"groups":[
 {"name":"mine","file":"f","extra":1,"rules":[
  {"type":"alerting","name":"A","labels":{"namespace":"a"},"custom":"kept"},
  {"type":"alerting","name":"B","labels":{"namespace":"b"}},
  {"type":"recording","name":"C"}]},
 {"name":"theirs","rules":[{"type":"recording","name":"D","labels":{"namespace":"b"}}]}]},
 "warnings":["w"]}`

func TestRules_Filtered(t *testing.T) {
	for _, prefix := range []string{"", "/prometheus"} {
		t.Run("prefix "+prefix, func(t *testing.T) {
			e := newEnv(t)
			e.respond = func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, rulesBody) }
			path := prefix + "/api/v1/rules"
			rec := e.serve(get(t, path), scoped(t, "GET", path, tenantA(), prefix))
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.Contains(t, body, `"A"`)
			assert.Contains(t, body, `"custom":"kept"`, "fields beyond the standard shape survive")
			assert.Contains(t, body, `"warnings":["w"]`)
			for _, other := range []string{`"B"`, `"C"`, `"D"`, `theirs`} {
				assert.NotContains(t, body, other)
			}
		})
	}
}

func TestRules_SeveralLabelsMustAllMatch(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","data":{"groups":[{"name":"g","rules":[
		 {"name":"both","labels":{"namespace":"a","cluster":"x"}},
		 {"name":"one","labels":{"namespace":"a"}}]}]}}`)
	}
	ls := []Label{{Name: "namespace", Values: []string{"a", "b"}}, {Name: "cluster", Values: []string{"x"}}}
	rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", ls))
	assert.Contains(t, rec.Body.String(), `"both"`)
	assert.NotContains(t, rec.Body.String(), `"one"`)
}

func TestAlerts_Filtered(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","data":{"alerts":[
		 {"labels":{"alertname":"mine","namespace":"a"}},
		 {"labels":{"alertname":"theirs","namespace":"b"}},
		 {"labels":{"alertname":"unlabelled"}}]}}`)
	}
	rec := e.serve(get(t, "/api/v1/alerts"), scoped(t, "GET", "/api/v1/alerts", tenantA()))
	assert.Contains(t, rec.Body.String(), "mine")
	assert.NotContains(t, rec.Body.String(), "theirs")
	assert.NotContains(t, rec.Body.String(), "unlabelled")
}

func TestFilter_GzipResponse(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, rulesBody)
		_ = gz.Close()
	}
	rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Content-Encoding"))
	assert.NotContains(t, rec.Body.String(), `"B"`)
}

func TestFilter_UnreadableIsNeverForwarded(t *testing.T) {
	tests := []struct {
		name string
		set  func(w http.ResponseWriter)
	}{
		{"not json", func(w http.ResponseWriter) { _, _ = io.WriteString(w, `secret: "x"`) }},
		{"not success", func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"status":"odd","data":{"groups":[]}}`) }},
		{"wrong shape", func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"status":"success","data":{"groups":"secret"}}`)
		}},
		{"unknown encoding", func(w http.ResponseWriter) {
			w.Header().Set("Content-Encoding", "br")
			_, _ = io.WriteString(w, "secret")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.respond = func(w http.ResponseWriter, _ *http.Request) { tt.set(w) }
			rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
			assert.Equal(t, http.StatusBadGateway, rec.Code)
			assert.NotContains(t, rec.Body.String(), "secret")
		})
	}
}

func TestFilter_ErrorStatusPasses(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "down")
	}
	rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestSilences_ListFiltered(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[
		 {"id":"mine","matchers":[{"name":"namespace","value":"a","isRegex":false}]},
		 {"id":"theirs","matchers":[{"name":"namespace","value":"b","isRegex":false}]},
		 {"id":"regex","matchers":[{"name":"namespace","value":"a","isRegex":true}]},
		 {"id":"negative","matchers":[{"name":"namespace","value":"a","isRegex":false,"isEqual":false}]},
		 {"id":"none","matchers":[{"name":"job","value":"x","isRegex":false}]}]`)
	}
	rec := e.serve(get(t, "/api/v2/silences"), scoped(t, "GET", "/api/v2/silences", tenantA()))
	require.Equal(t, http.StatusOK, rec.Code)
	var got []struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 1)
	assert.Equal(t, "mine", got[0].ID)
}

func silenceReq(t *testing.T, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v2/silences", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func matchersOf(t *testing.T, body string) []matcher {
	t.Helper()
	var s silence
	require.NoError(t, json.Unmarshal([]byte(body), &s))
	return s.Matchers
}

func TestSilences_Create(t *testing.T) {
	job := `{"name":"job","value":"x","isRegex":false}`
	several := []Label{{Name: "namespace", Values: []string{"a", "b"}}}

	t.Run("single value is set", func(t *testing.T) {
		e := newEnv(t)
		rec := e.serve(silenceReq(t, `{"comment":"c","matchers":[`+job+`]}`), scoped(t, "POST", "/api/v2/silences", tenantA()))
		require.Equal(t, http.StatusOK, rec.Code)
		got := e.last(t)
		assert.Contains(t, matchersOf(t, got.body), matcher{Name: "namespace", Value: "a"})
		assert.Contains(t, got.body, `"comment":"c"`, "other fields survive")
	})
	t.Run("several values, one named", func(t *testing.T) {
		e := newEnv(t)
		rec := e.serve(silenceReq(t, `{"matchers":[`+job+`,{"name":"namespace","value":"b","isRegex":false}]}`), scoped(t, "POST", "/api/v2/silences", several))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, matchersOf(t, e.last(t).body), matcher{Name: "namespace", Value: "b"})
	})

	refused := []struct {
		name, body string
		ls         []Label
		status     int
	}{
		{"several values, none named", `{"matchers":[` + job + `]}`, several, 400},
		{"foreign value", `{"matchers":[` + job + `,{"name":"namespace","value":"z","isRegex":false}]}`, tenantA(), 403},
		{"regex on the label", `{"matchers":[` + job + `,{"name":"namespace","value":"a|z","isRegex":true}]}`, tenantA(), 403},
		{"negative on the label", `{"matchers":[` + job + `,{"name":"namespace","value":"a","isRegex":false,"isEqual":false}]}`, tenantA(), 403},
		{"two on the label", `{"matchers":[` + job + `,{"name":"namespace","value":"a","isRegex":false},{"name":"namespace","value":"b","isRegex":false}]}`, several, 400},
		{"only the label", `{"matchers":[{"name":"namespace","value":"a","isRegex":false}]}`, tenantA(), 400},
		{"no matchers", `{"matchers":[]}`, tenantA(), 400},
		{"not json", `nope`, tenantA(), 400},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			rec := e.serve(silenceReq(t, tt.body), scoped(t, "POST", "/api/v2/silences", tt.ls))
			assert.Equal(t, tt.status, rec.Code, rec.Body.String())
			assert.Zero(t, e.count(), "must not reach the backend")
		})
	}
}

// silenceBackend answers lookups with stored and records the rest.
func silenceBackend(stored map[string]string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			return
		}
		body, ok := stored[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, body)
	}
}

func TestSilences_DeleteAndUpdate(t *testing.T) {
	stored := map[string]string{
		"/am/api/v2/silence/aaaa": `{"matchers":[{"name":"namespace","value":"a","isRegex":false}]}`,
		"/am/api/v2/silence/bbbb": `{"matchers":[{"name":"namespace","value":"b","isRegex":false}]}`,
	}
	ls := tenantA()

	del := func(t *testing.T, e *env, id string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/am/api/v2/silence/" + id
		r := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, path, nil)
		return e.serve(r, scoped(t, "DELETE", path, ls, "/am"))
	}

	t.Run("delete own", func(t *testing.T) {
		e := newEnv(t)
		e.respond = silenceBackend(stored)
		require.Equal(t, http.StatusOK, del(t, e, "aaaa").Code)
		assert.Equal(t, http.MethodDelete, e.last(t).method)
		assert.Equal(t, "/am/api/v2/silence/aaaa", e.last(t).path)
	})
	t.Run("delete another tenant's", func(t *testing.T) {
		e := newEnv(t)
		e.respond = silenceBackend(stored)
		assert.Equal(t, http.StatusForbidden, del(t, e, "bbbb").Code)
		assert.Equal(t, http.MethodGet, e.last(t).method, "only the lookup reached the backend")
	})
	t.Run("delete missing looks the same", func(t *testing.T) {
		e := newEnv(t)
		e.respond = silenceBackend(stored)
		assert.Equal(t, http.StatusForbidden, del(t, e, "cccc").Code)
	})
	t.Run("bad id", func(t *testing.T) {
		e := newEnv(t)
		assert.Equal(t, http.StatusBadRequest, del(t, e, "..").Code)
		assert.Zero(t, e.count())
	})

	update := func(t *testing.T, id string) (*env, *httptest.ResponseRecorder) {
		t.Helper()
		e := newEnv(t)
		e.respond = silenceBackend(stored)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/am/api/v2/silences",
			strings.NewReader(`{"id":"`+id+`","matchers":[{"name":"job","value":"x","isRegex":false}]}`))
		return e, e.serve(r, scoped(t, "POST", "/am/api/v2/silences", ls, "/am"))
	}
	t.Run("update own", func(t *testing.T) {
		e, rec := update(t, "aaaa")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, http.MethodPost, e.last(t).method)
	})
	t.Run("update another tenant's", func(t *testing.T) {
		e, rec := update(t, "bbbb")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, http.MethodGet, e.last(t).method)
	})
}

func TestFilterSurvivesContextThroughTransport(t *testing.T) {
	// ModifyResponse finds the filter on the response's request context, which
	// the instrumented transport must carry through. Losing it would forward
	// the response unfiltered, so this pins it on the real transport.
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, rulesBody) }
	rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
	assert.NotContains(t, rec.Body.String(), `"B"`)
}

// testEnforcer is the enforcer Handler.rewrite builds for one value.
func testEnforcer(t *testing.T) *promqlEnforcer {
	t.Helper()
	e, err := newPromQLEnforcer(Scope{Labels: tenantA()})
	require.NoError(t, err)
	return e
}

func TestEnforce_EverySelector(t *testing.T) {
	e := testEnforcer(t)
	tests := []struct{ in, want string }{
		{`a + b`, `a{namespace="a"} + b{namespace="a"}`},
		{`-a`, `-a{namespace="a"}`},
		{`(a)`, `(a{namespace="a"})`},
		{`a offset 5m`, `a{namespace="a"} offset 5m`},
		{`a @ 10`, `a{namespace="a"} @ 10.000`},
		{`rate(a[5m])`, `rate(a{namespace="a"}[5m])`},
		{`topk(1, a)`, `topk(1, a{namespace="a"})`},
		{`avg_over_time(rate(a[5m])[1h:1m])`, `avg_over_time(rate(a{namespace="a"}[5m])[1h:1m])`},
		{`a and on (x) b`, `a{namespace="a"} and on (x) b{namespace="a"}`},
		{`label_replace(a, "x", "$1", "y", "(.*)")`, `label_replace(a{namespace="a"}, "x", "$1", "y", "(.*)")`},
		{`{__name__=~".+"}`, `{__name__=~".+",namespace="a"}`},
		{`topk(scalar(secret), up)`, `topk(scalar(secret{namespace="a"}), up{namespace="a"})`},
		{`quantile(scalar(secret), up)`, `quantile(scalar(secret{namespace="a"}), up{namespace="a"})`},
		{`limitk(1, up)`, `limitk(1, up{namespace="a"})`},
		{`sort_by_label(up, "x")`, `sort_by_label(up{namespace="a"}, "x")`},
		{`1 + 1`, `1 + 1`},
	}
	for _, tt := range tests {
		got, err := e.enforce(tt.in)
		require.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got)
	}
}

func TestEnforce_NegatedCallerMatchers(t *testing.T) {
	e := testEnforcer(t)

	_, err := e.enforce(`up{namespace!="a"}`)
	require.ErrorIs(t, err, injectproxy.ErrIllegalLabelMatcher)
	_, err = e.enforce(`up{namespace!~"a|b"}`)
	require.ErrorIs(t, err, injectproxy.ErrIllegalLabelMatcher)

	got, err := e.enforce(`up{namespace!="b"}`)
	require.NoError(t, err)
	assert.Equal(t, `up{namespace="a"}`, got, "the enforced value already satisfies it")
}

// A conflict in the last selector must still fail the whole query.
func TestEnforce_ConflictInLastSelector(t *testing.T) {
	e := testEnforcer(t)
	_, err := e.enforce(`a + b + c{namespace="z"}`)
	require.ErrorIs(t, err, injectproxy.ErrIllegalLabelMatcher)
	_, err = e.enforce(`a{namespace="z"} + b`)
	require.ErrorIs(t, err, injectproxy.ErrIllegalLabelMatcher, "a later selector must not clear it")
}

// encoding/json folds case, including U+017F to "s", and a backend reading the
// body takes the last alias. Only what was checked may leave.
func TestSilences_KeyAliases(t *testing.T) {
	stored := map[string]string{"/api/v2/silence/bbbb": `{"matchers":[{"name":"namespace","value":"b","isRegex":false}]}`}
	job := `{"name":"job","value":"x","isRegex":false}`

	t.Run("matchers alias can't replace the scoped list", func(t *testing.T) {
		e := newEnv(t)
		body := `{"matchers":[` + job + `],"matcherſ":[{"name":"alertname","value":".*","isRegex":true}],"Matchers":[` + job + `]}`
		rec := e.serve(silenceReq(t, body), scoped(t, "POST", "/api/v2/silences", tenantA()))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		got := e.last(t).body
		assert.NotContains(t, got, "matcherſ")
		assert.NotContains(t, got, "Matchers")
		var decoded struct {
			Matchers []matcher `json:"matchers"`
		}
		require.NoError(t, json.Unmarshal([]byte(got), &decoded))
		assert.Contains(t, decoded.Matchers, matcher{Name: "namespace", Value: "a"})
	})
	for _, key := range []string{"ID", "Id", "iD"} {
		t.Run("id alias "+key+" is still checked", func(t *testing.T) {
			e := newEnv(t)
			e.respond = silenceBackend(stored)
			body := `{"` + key + `":"bbbb","matchers":[` + job + `]}`
			rec := e.serve(silenceReq(t, body), scoped(t, "POST", "/api/v2/silences", tenantA()))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, http.MethodGet, e.last(t).method, "only the lookup reached the backend")
		})
	}
	t.Run("other fields survive", func(t *testing.T) {
		e := newEnv(t)
		body := `{"comment":"c","createdBy":"me","startsAt":"2026-01-01T00:00:00Z","endsAt":"2026-01-02T00:00:00Z","matchers":[` + job + `]}`
		e.serve(silenceReq(t, body), scoped(t, "POST", "/api/v2/silences", tenantA()))
		got := e.last(t).body
		for _, want := range []string{`"comment":"c"`, `"createdBy":"me"`, `"startsAt":"2026-01-01T00:00:00Z"`, `"endsAt":"2026-01-02T00:00:00Z"`} {
			assert.Contains(t, got, want)
		}
	})
}

func TestFilter_OtherStatusesRefused(t *testing.T) {
	for _, status := range []int{http.StatusPartialContent, http.StatusNonAuthoritativeInfo} {
		e := newEnv(t)
		e.respond = func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, rulesBody)
		}
		rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.NotContains(t, rec.Body.String(), `"B"`)
	}
}

func TestFilter_PartialRequestHeadersDropped(t *testing.T) {
	e := newEnv(t)
	var seen http.Header
	e.respond = func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.WriteString(w, rulesBody)
	}
	r := get(t, "/api/v1/rules")
	r.Header.Set("Range", "bytes=0-10")
	r.Header.Set("If-None-Match", `"x"`)
	e.serve(r, scoped(t, "GET", "/api/v1/rules", tenantA()))
	assert.Empty(t, seen.Get("Range"))
	assert.Empty(t, seen.Get("If-None-Match"))
}

func TestFilter_OversizedResponseRefused(t *testing.T) {
	e := newEnv(t)
	e.respond = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","data":{"groups":[],"pad":"`)
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes))
		_, _ = io.WriteString(w, `"}}`)
	}
	rec := e.serve(get(t, "/api/v1/rules"), scoped(t, "GET", "/api/v1/rules", tenantA()))
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}
