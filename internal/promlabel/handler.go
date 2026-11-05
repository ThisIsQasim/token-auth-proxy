package promlabel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const (
	queryParam  = "query"
	matchParam  = "match[]"
	filterParam = "filter"

	// maxBodyBytes bounds a request body held in memory for rewriting.
	maxBodyBytes = 10 << 20

	formContentType = "application/x-www-form-urlencoded"
)

// ConfigSource supplies the currently-live config.
type ConfigSource interface {
	Current() *config.Config
}

// Handler enforces the request's Scope, then passes it to next.
type Handler struct {
	source    ConfigSource
	next      http.Handler
	transport http.RoundTripper
	logger    *slog.Logger
}

// New builds a Handler forwarding to next. transport is what next forwards
// with, used here for the silence lookups an ownership check needs.
func New(source ConfigSource, next http.Handler, transport http.RoundTripper, logger *slog.Logger) *Handler {
	return &Handler{source: source, next: next, transport: transport, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scope, ok := scopeFrom(r.Context())
	if !ok {
		// Enforcement configured but no verdict means a request got here some
		// way other than through authn: refuse it rather than forward it bare.
		if h.source.Current().Outbound.PromLabelProxy != nil {
			h.logger.ErrorContext(r.Context(), "prom_label_proxy: request without a verdict", "path", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}
	if scope.Bypass {
		h.next.ServeHTTP(w, r)
		return
	}

	r = r.Clone(r.Context())
	switch scope.Endpoint {
	case endpointQuery:
		h.rewrite(w, r, scope, enforceQuery)
	case endpointMatch:
		h.rewrite(w, r, scope, enforceMatch)
	case endpointRules:
		h.filtered(w, r, scope, filterRules)
	case endpointAlerts:
		h.filtered(w, r, scope, filterAlerts)
	case endpointAMFilter:
		h.amFilter(w, r, scope)
	case endpointSilences:
		if r.Method == http.MethodPost {
			h.postSilence(w, r, scope)
			return
		}
		h.filteredRaw(w, r, scope, filterSilences)
	case endpointSilenceID:
		h.deleteSilence(w, r, scope)
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

// enforcer rewrites one location's parameters. found reports whether they
// held anything to enforce.
type enforcer func(e *promqlEnforcer, v url.Values) (found bool, err error)

// rewrite enforces both places a Prometheus parameter can arrive, the URL and
// a form body, re-encoding each so what the backend parses is what was checked.
func (h *Handler) rewrite(w http.ResponseWriter, r *http.Request, scope Scope, enforce enforcer) {
	matchers, err := scope.matchers()
	if err != nil {
		promError(w, http.StatusInternalServerError, err)
		return
	}
	e, err := newPromQLEnforcer(scope)
	if err != nil {
		promError(w, http.StatusInternalServerError, err)
		return
	}

	urlValues, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		promError(w, http.StatusBadRequest, err)
		return
	}
	body, status, err := readForm(w, r)
	if err != nil {
		promError(w, status, err)
		return
	}

	foundURL, err := enforce(e, urlValues)
	if err != nil {
		promError(w, enforceStatus(err), err)
		return
	}
	foundBody, err := enforce(e, body)
	if err != nil {
		promError(w, enforceStatus(err), err)
		return
	}

	if !foundURL && !foundBody {
		if scope.Endpoint == endpointQuery {
			promError(w, http.StatusBadRequest, errors.New("missing query parameter"))
			return
		}
		urlValues.Set(matchParam, matchersSelector(matchers))
	}

	r.URL.RawQuery = urlValues.Encode()
	setBody(r, body.Encode(), formContentType)
	h.next.ServeHTTP(w, r)
}

// readForm reads the form out of r; the caller replaces the body, so one sent
// on a GET is dropped rather than forwarded. Anything but a
// urlencoded body is refused: a backend reading parameters with FormValue
// also parses multipart bodies, on any method, which would otherwise carry an
// unenforced query straight past this check.
func readForm(w http.ResponseWriter, r *http.Request) (url.Values, int, error) {
	if r.Method != http.MethodPost {
		return url.Values{}, 0, nil
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != formContentType {
			return nil, http.StatusUnsupportedMediaType, fmt.Errorf("unsupported content type %q", ct)
		}
	}
	raw, err := readBody(w, r)
	if err != nil {
		return nil, http.StatusRequestEntityTooLarge, err
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	return values, 0, nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
}

func dropBody(r *http.Request) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	r.Body = http.NoBody
	r.ContentLength = 0
	r.Header.Del("Content-Length")
	r.Header.Del("Content-Type")
	r.Header.Del("Transfer-Encoding")
	r.TransferEncoding = nil
}

func setBody(r *http.Request, body, contentType string) {
	if body == "" {
		dropBody(r)
		return
	}
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.Header.Set("Content-Type", contentType)
	r.TransferEncoding = nil
}

// enforceQuery enforces the query parameter. More than one value is refused:
// backends differ in which one they read, and only one can be checked as "the
// query". An empty value fails as a parse error, for the same reason.
func enforceQuery(e *promqlEnforcer, v url.Values) (bool, error) {
	if !v.Has(queryParam) {
		return false, nil
	}
	if len(v[queryParam]) != 1 {
		return false, fmt.Errorf("%w: more than one query parameter", injectproxy.ErrQueryParse)
	}
	q, err := e.enforce(v.Get(queryParam))
	if err != nil {
		return false, err
	}
	v.Set(queryParam, q)
	return true, nil
}

// enforceMatch enforces every match[] selector.
func enforceMatch(e *promqlEnforcer, v url.Values) (bool, error) {
	selectors := v[matchParam]
	for i, s := range selectors {
		enforced, err := e.enforce(s)
		if err != nil {
			return false, err
		}
		selectors[i] = enforced
	}
	return len(selectors) > 0, nil
}

// enforceStatus maps an enforcer error: a query the caller got wrong is theirs
// to fix, anything else is ours.
func enforceStatus(err error) int {
	if errors.Is(err, injectproxy.ErrQueryParse) || errors.Is(err, injectproxy.ErrIllegalLabelMatcher) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// amFilter adds the enforced matchers to Alertmanager's filter parameter. Its
// filters are ANDed, so the caller's own can stay and can only narrow further.
func (h *Handler) amFilter(w http.ResponseWriter, r *http.Request, scope Scope) {
	matchers, err := scope.matchers()
	if err != nil {
		promError(w, http.StatusInternalServerError, err)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, m := range matchers {
		q.Add(filterParam, m.String())
	}
	r.URL.RawQuery = q.Encode()
	dropBody(r)
	h.next.ServeHTTP(w, r)
}

func (s Scope) matchers() ([]*labels.Matcher, error) {
	out := make([]*labels.Matcher, 0, len(s.Labels))
	for _, l := range s.Labels {
		m, err := l.matcher()
		if err != nil {
			return nil, fmt.Errorf("label %q: %w", l.Name, err)
		}
		out = append(out, m)
	}
	return out, nil
}

func matchersSelector(ms []*labels.Matcher) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = m.String()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// promError writes an error in the Prometheus API's own shape, which is what
// its clients know how to show.
func promError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "error",
		"errorType": "prom_label_proxy",
		"error":     err.Error(),
	})
}
