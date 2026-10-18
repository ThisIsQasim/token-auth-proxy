package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	tu "github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

const loginClientID = "proxy-client"

// loginEnv is a real HTTP server running the middleware in front of a
// backend that echoes the request URI it was reached at, so a test can
// follow the whole browser flow with a cookie-jar client.
type loginEnv struct {
	idp     *tu.TestIDP
	server  *httptest.Server
	backend atomic.Int64
	source  *fakeSource
	login   *LoginRegistry
}

type loginOpts struct {
	secret string // empty: public client
	method string // token_auth_method
	basic  bool

	refresh bool // login.refresh, with the IdP issuing refresh tokens
	rotate  bool // the IdP rotates refresh tokens
}

func newLoginEnv(t *testing.T, o loginOpts) *loginEnv {
	t.Helper()
	e := &loginEnv{idp: tu.NewTestIDP(t)}
	e.idp.RegisterClient(loginClientID, o.secret)

	var handler http.Handler
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.server.Close)

	lg := &config.JWTLogin{ClientID: loginClientID, SPBaseURL: e.server.URL, CallbackPath: "/_tap/oidc/callback", CookieName: "tap_id_token", Scopes: []string{"openid", "profile"}}
	if o.refresh {
		lg.Refresh, lg.RefreshMaxAge = true, 24*time.Hour
		lg.Scopes = append(lg.Scopes, "offline_access")
		e.idp.EnableRefresh(o.rotate)
	}
	if o.secret != "" {
		lg.ClientSecret, lg.TokenAuthMethod = o.secret, o.method
	}
	src := config.JWTSource{
		Name: "idp", Issuer: e.idp.Issuer, OIDCDiscoveryURL: e.idp.DiscoveryURL,
		Audiences: []string{loginClientID}, Algorithms: []string{"RS256"},
		Credentials: []config.CredentialLocation{
			{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			{Location: "cookie", Name: "tap_id_token"},
		},
		Login: lg,
	}
	auth := config.InboundAuthConfig{JWT: []config.JWTSource{src}}
	if o.basic {
		b := basicSourceFor(t)
		auth.Basic = &b
	}
	e.source = newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: auth}})

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	saml := NewSAMLRegistry(testLogger())
	t.Cleanup(saml.Close)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.backend.Add(1)
		var names []string
		for _, c := range r.Cookies() {
			names = append(names, c.Name)
		}
		w.Header().Set("X-Seen-Cookies", strings.Join(names, ","))
		w.Header().Set("X-Seen-Cookie-Header", strings.Join(r.Header.Values("Cookie"), " | "))
		_, _ = io.WriteString(w, "backend:"+r.URL.RequestURI())
	})
	e.login = NewLoginRegistry(reg, testLogger())
	handler = NewMiddleware(e.source, reg, saml, NewBasicRegistry(testLogger()), e.login, testLogger())(backend)
	return e
}

func (e *loginEnv) client(t *testing.T, follow bool) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// pageResp is a response whose body has already been read and closed.
type pageResp struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
}

func (p *pageResp) Cookies() []*http.Cookie { return p.cookies }

func (e *loginEnv) get(t *testing.T, c *http.Client, path string, hdr map[string]string) (*pageResp, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.server.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return &pageResp{StatusCode: resp.StatusCode, Header: resp.Header, cookies: resp.Cookies()}, string(body)
}

func TestLogin_ConfidentialClient_Basic(t *testing.T) {
	e := newLoginEnv(t, loginOpts{secret: "s3cret", method: config.TokenAuthBasic})
	c := e.client(t, true)

	resp, body := e.get(t, c, "/dash/board?x=1", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/dash/board?x=1", body, "must land on the originally requested URL")

	tr := e.idp.LastTokenRequest()
	assert.Equal(t, "basic", tr.AuthMethod)
	assert.True(t, tr.SecretOK)
	assert.True(t, tr.VerifierOK, "PKCE is used for confidential clients too")

	// The cookie now authenticates without another round trip to the IdP.
	before := e.idp.LastTokenRequest()
	resp, body = e.get(t, c, "/again", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/again", body)
	assert.Equal(t, before, e.idp.LastTokenRequest())
}

func TestLogin_ConfidentialClient_Post(t *testing.T) {
	e := newLoginEnv(t, loginOpts{secret: "s3cret", method: config.TokenAuthPost})
	resp, _ := e.get(t, e.client(t, true), "/", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "post", e.idp.LastTokenRequest().AuthMethod)
}

func TestLogin_PublicClient_PKCE(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	resp, body := e.get(t, e.client(t, true), "/x", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/x", body)

	tr := e.idp.LastTokenRequest()
	assert.Equal(t, "none", tr.AuthMethod, "a public client must send no secret")
	assert.True(t, tr.VerifierOK)
}

func TestLogin_NonBrowserRequestGets401NotRedirect(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	for name, tc := range map[string]map[string]string{
		"json":   {"Accept": "application/json"},
		"no-hdr": {"Accept": ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp, _ := e.get(t, e.client(t, false), "/api", tc)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Contains(t, resp.Header.Values("WWW-Authenticate"), bearerChallenge)
		})
	}
	assert.Zero(t, e.backend.Load())
}

func TestLogin_RedirectsToIdPWithPKCEAndNonce(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	resp, _ := e.get(t, e.client(t, false), "/", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	assert.Equal(t, e.idp.AuthorizeURL(), loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, loginClientID, q.Get("client_id"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.NotEmpty(t, q.Get("state"))
	assert.NotEmpty(t, q.Get("nonce"))
	assert.Equal(t, e.server.URL+"/_tap/oidc/callback", q.Get("redirect_uri"))
	assert.Equal(t, "openid profile", q.Get("scope"))

	var state *http.Cookie
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, loginStateCookie) {
			state = ck
		}
	}
	require.NotNil(t, state)
	assert.True(t, state.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, state.SameSite)
}

func TestLogin_CallbackRejections(t *testing.T) {
	cases := map[string]struct {
		path   func(state string) string
		status int
	}{
		"no state cookie": {
			path:   func(string) string { return "/_tap/oidc/callback?code=x&state=y" },
			status: http.StatusBadRequest,
		},
		"state mismatch": {
			path:   func(string) string { return "/_tap/oidc/callback?code=x&state=wrong" },
			status: http.StatusBadRequest,
		},
		"idp error": {
			path:   func(s string) string { return "/_tap/oidc/callback?error=access_denied&state=" + s },
			status: http.StatusForbidden,
		},
		"missing code": {
			path:   func(s string) string { return "/_tap/oidc/callback?state=" + s },
			status: http.StatusBadRequest,
		},
		"bad code": {
			path:   func(s string) string { return "/_tap/oidc/callback?code=bogus&state=" + s },
			status: http.StatusBadGateway,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLoginEnv(t, loginOpts{})
			c := e.client(t, false)
			var state string
			if name != "no state cookie" {
				resp, _ := e.get(t, c, "/", nil)
				loc, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				state = loc.Query().Get("state")
			}
			resp, _ := e.get(t, c, tc.path(state), nil)
			assert.Equal(t, tc.status, resp.StatusCode)
			assert.Zero(t, e.backend.Load())
			for _, ck := range resp.Cookies() {
				assert.NotEqual(t, "tap_id_token", ck.Name, "no session cookie on a failed login")
			}
		})
	}
}

func TestLogin_StateCookieIsSingleUse(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, false)

	resp, _ := e.get(t, c, "/", nil)
	authz := resp.Header.Get("Location")
	// Follow the IdP redirect manually to get the callback URL.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authz, nil)
	require.NoError(t, err)
	idpResp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	require.NoError(t, err)
	_ = idpResp.Body.Close()
	cb := idpResp.Header.Get("Location")

	cbPath := strings.TrimPrefix(cb, e.server.URL)
	first, _ := e.get(t, c, cbPath, nil)
	assert.Equal(t, http.StatusFound, first.StatusCode)

	second, _ := e.get(t, c, cbPath, nil)
	assert.Equal(t, http.StatusBadRequest, second.StatusCode, "replaying the callback must fail")
}

func TestLogin_RejectsTokenWithoutNonce(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	e.idp.OmitNonce()
	resp, _ := e.get(t, e.client(t, true), "/", nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, e.backend.Load())
}

func TestLogin_ExpiredTokenIsNotStored(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	e.idp.SetLoginTTL(-time.Minute)
	resp, _ := e.get(t, e.client(t, true), "/", nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, e.backend.Load())
}

func TestLogin_IdPUnavailable(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	e.idp.Server.Close()
	resp, _ := e.get(t, e.client(t, false), "/", nil)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestLogin_ACLUsesIDTokenClaims(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	e.idp.SetLoginUser("carol", map[string]any{"groups": []string{"admins"}})
	next := *e.source.Current()
	next.ACL = []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: config.ACLModeJWT, Claims: map[string]string{"groups": "admins"}}},
	}}
	e.source.set(&next)

	resp, body := e.get(t, e.client(t, true), "/", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/", body)

	e.idp.SetLoginUser("dave", map[string]any{"groups": []string{"staff"}})
	resp, _ = e.get(t, e.client(t, true), "/", nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSanitizeReturnTo(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "/",
		"/":                      "/",
		"/a/b?x=1&y=2":           "/a/b?x=1&y=2",
		"//evil.example":         "/",
		"/\\evil.example":        "/",
		"https://evil.example/":  "/",
		"javascript:alert(1)":    "/",
		"relative":               "/",
		"/_tap/login":            "/",
		"/_tap/login/jwt?x=1":    "/",
		"/ok\r\nSet-Cookie: a=b": "/",
	} {
		assert.Equal(t, want, sanitizeReturnTo(in), "input %q", in)
	}
}

func TestPicker_TwoMethods(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)

	// A browser with no credential is sent to the picker, not an IdP.
	resp, _ := e.get(t, c, "/some/page?q=1", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, config.LoginPathPrefix, loc.Path)
	assert.Equal(t, "/some/page?q=1", loc.Query().Get("return_to"))

	// The picker lists both methods.
	resp, body := e.get(t, c, loc.RequestURI(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	assert.Contains(t, body, "Sign in with idp")
	assert.Contains(t, body, "Sign in with username and password")
	assert.Contains(t, body, "/_tap/login/basic?return_to=%2Fsome%2Fpage%3Fq%3D1")
	assert.Zero(t, e.backend.Load())

	// Non-browser requests are unchanged: a plain 401 with both challenges.
	resp, _ = e.get(t, c, "/api", map[string]string{"Accept": "application/json"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Len(t, resp.Header.Values("WWW-Authenticate"), 2)
}

func TestPicker_ChooseOIDC(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, true)
	resp, body := e.get(t, c, "/_tap/login/jwt?source=idp&return_to=%2Fafter", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/after", body)
}

func TestPicker_ChooseBasic(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)

	// Without credentials the entry point issues the challenge.
	resp, _ := e.get(t, c, "/_tap/login/basic?return_to=%2Fafter", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Www-Authenticate"), `Basic realm="test-realm"`)

	// A wrong password is refused and does not record the choice.
	resp, _ = e.get(t, c, "/_tap/login/basic?return_to=%2Fafter", map[string]string{"Authorization": basicHeader("alice", "nope")})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// The right one redirects back and remembers the choice...
	resp, _ = e.get(t, c, "/_tap/login/basic?return_to=%2Fafter", map[string]string{"Authorization": basicHeader("alice", "hunter2")})
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/after", resp.Header.Get("Location"))

	// ...so the next credential-less navigation is challenged with Basic
	// only, which is what makes the browser resend its cached credentials.
	resp, _ = e.get(t, c, "/after", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, []string{`Basic realm="test-realm", charset="UTF-8"`}, resp.Header.Values("WWW-Authenticate"))

	resp, body := e.get(t, c, "/after", map[string]string{"Authorization": basicHeader("alice", "hunter2")})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/after", body)
}

func TestPicker_RemembersOIDCChoice(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)
	resp, _ := e.get(t, c, "/_tap/login/jwt?source=idp&return_to=%2F", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// With the choice remembered, a fresh navigation goes straight to the IdP.
	resp, _ = e.get(t, c, "/page", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), e.idp.AuthorizeURL()))
}

func TestPicker_UnknownRoutes(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)
	for _, p := range []string{"/_tap/login/saml", "/_tap/login/nope", "/_tap/login/jwt?source=other"} {
		resp, _ := e.get(t, c, p, nil)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, p)
	}
}

func basicHeader(_, p string) string {
	r := &http.Request{Header: http.Header{}}
	r.SetBasicAuth("alice", p)
	return r.Header.Get("Authorization")
}

func TestPicker_CustomCSS(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)

	_, body := e.get(t, c, "/_tap/login", nil)
	assert.NotContains(t, body, "brand-override")

	next := *e.source.Current()
	next.Inbound.Auth.LoginPage = &config.LoginPageConfig{CSS: ":root { --accent: #c00; } /* brand-override */ .tap-login-method > b { color: red; }"}
	e.source.set(&next)

	resp, body := e.get(t, c, "/_tap/login", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "<style>:root { --accent: #c00; } /* brand-override */ .tap-login-method > b { color: red; }</style>")
	assert.Less(t, strings.Index(body, "--accent-fg"), strings.Index(body, "brand-override"), "custom CSS comes after the defaults so it overrides them")
	assert.Contains(t, body, `class="tap-login-method"`)
}

// expireSession drops the ID token cookie from c, as a browser does when
// the cookie's Max-Age runs out, leaving any refresh cookie in place.
func (e *loginEnv) expireSession(t *testing.T, c *http.Client) {
	t.Helper()
	u, err := url.Parse(e.server.URL)
	require.NoError(t, err)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "tap_id_token", Value: "", Path: "/", MaxAge: -1}})
}

func cookieNames(c *http.Client, base string) []string {
	u, _ := url.Parse(base)
	var out []string
	for _, ck := range c.Jar.Cookies(u) {
		out = append(out, ck.Name)
	}
	return out
}

func TestRefresh_LoginStoresRefreshCookie(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	resp, _ := e.get(t, c, "/", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.ElementsMatch(t, []string{"tap_id_token", "tap_id_token_refresh"}, cookieNames(c, e.server.URL))
	assert.NotContains(t, resp.Header.Get("X-Seen-Cookies"), "tap_id_token_refresh", "the refresh token must not reach the backend")
}

func TestRefresh_OffStoresNoRefreshCookie(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	e.idp.EnableRefresh(false) // the IdP would issue one; the proxy must not keep it
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	assert.Equal(t, []string{"tap_id_token"}, cookieNames(c, e.server.URL))
}

func TestRefresh_RenewsExpiredSessionTransparently(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, rotate: true})
	follow := e.client(t, true)
	e.get(t, follow, "/", nil)
	before := e.idp.RefreshCalls()
	e.expireSession(t, follow)

	// A non-browser request is renewed too, and reaches the backend.
	resp, body := e.get(t, follow, "/api/x", map[string]string{"Accept": "application/json"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/api/x", body)
	assert.Equal(t, before+1, e.idp.RefreshCalls())
	assert.NotContains(t, resp.Header.Get("X-Seen-Cookies"), "_refresh", "the refresh token must not reach the backend")
	assert.Contains(t, resp.Header.Get("X-Seen-Cookies"), "tap_id_token", "the backend sees the renewed session like any other")
	assert.ElementsMatch(t, []string{"tap_id_token", "tap_id_token_refresh"}, cookieNames(follow, e.server.URL))

	// And the next request needs no refresh at all.
	resp, _ = e.get(t, follow, "/api/y", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, before+1, e.idp.RefreshCalls())
}

func TestRefresh_RotatedTokenIsUsedNext(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, rotate: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)

	for i := 1; i <= 3; i++ {
		e.expireSession(t, c)
		resp, _ := e.get(t, c, "/", nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "renewal %d", i)
	}
	assert.Equal(t, 3, e.idp.RefreshCalls(), "each renewal redeems the newest refresh token, which a rotating IdP accepts once")
}

func TestRefresh_ParallelRequestsShareOneRedemption(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, rotate: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	e.expireSession(t, c)
	e.idp.SetRefreshDelay(300 * time.Millisecond)

	const n = 8
	statuses := make(chan int, n)
	for range n {
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, e.server.URL+"/p", nil)
			req.Header.Set("Accept", "text/html")
			// Each request carries the same stale cookies, as parallel
			// requests from one browser tab do.
			u, _ := url.Parse(e.server.URL)
			for _, ck := range c.Jar.Cookies(u) {
				req.AddCookie(ck)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	for range n {
		assert.Equal(t, http.StatusOK, <-statuses)
	}
	assert.Equal(t, 1, e.idp.RefreshCalls(), "a rotating IdP would reject (or revoke on) a second redemption")
}

func TestRefresh_RejectedRefreshTokenFallsBackToLogin(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	e.expireSession(t, c)
	e.idp.RevokeRefreshTokens()

	nofollow := &http.Client{Jar: c.Jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := e.get(t, nofollow, "/page", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), e.idp.AuthorizeURL()), "a browser goes through a full login again")
	assert.NotContains(t, cookieNames(c, e.server.URL), "tap_id_token_refresh", "the dead refresh token is cleared")

	// An API client gets a plain 401 instead.
	e.expireSession(t, c)
	resp, _ = e.get(t, nofollow, "/api", map[string]string{"Accept": "application/json"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRefresh_IdPUnreachableIs503AndKeepsToken(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	e.expireSession(t, c)
	e.idp.Server.Close()

	resp, _ := e.get(t, c, "/", nil)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Contains(t, cookieNames(c, e.server.URL), "tap_id_token_refresh", "a transient failure must not log the user out")
}

func TestRefresh_ValidSessionDoesNotRefresh(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	for range 3 {
		resp, _ := e.get(t, c, "/", nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	assert.Zero(t, e.idp.RefreshCalls())
}

func TestLogin_ConcurrentLoginsInOneBrowser(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, false)

	// Two tabs start a login before either finishes.
	var callbacks []string
	for _, p := range []string{"/tab-a", "/tab-b"} {
		resp, _ := e.get(t, c, p, nil)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, resp.Header.Get("Location"), nil)
		require.NoError(t, err)
		idpResp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		require.NoError(t, err)
		_ = idpResp.Body.Close()
		callbacks = append(callbacks, strings.TrimPrefix(idpResp.Header.Get("Location"), e.server.URL))
	}

	for i, want := range []string{"/tab-a", "/tab-b"} {
		resp, _ := e.get(t, c, callbacks[i], nil)
		require.Equal(t, http.StatusFound, resp.StatusCode, "tab %d must not be clobbered by the other", i)
		assert.Equal(t, want, resp.Header.Get("Location"))
	}
}

func TestRefresh_CookieStrippedOnEveryPath(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, basic: true})
	c := e.client(t, false)

	// A Basic-authenticated request must not carry the refresh token to
	// the backend, and the backend's own cookies must arrive untouched.
	resp, _ := e.get(t, c, "/", map[string]string{
		"Authorization": basicHeader("alice", "hunter2"),
		"Cookie":        `a="x y"; tap_id_token_refresh=secret-rt; b=2`,
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `a="x y"; b=2`, resp.Header.Get("X-Seen-Cookie-Header"))
}

func TestPicker_BasicChoiceOffersWayBack(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)
	resp, _ := e.get(t, c, "/_tap/login/basic?return_to=%2Fafter", map[string]string{"Authorization": basicHeader("alice", "hunter2")})
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp, body := e.get(t, c, "/page", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Www-Authenticate"), "Basic realm")
	assert.Contains(t, body, `href="/_tap/login?return_to=%2Fpage"`, "canceling the password prompt must leave a way to pick another method")

	// The picker is still reachable and lets the user switch.
	resp, body = e.get(t, c, "/_tap/login?return_to=%2Fpage", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Sign in with idp")
}

func TestLogin_DiscoveryOutageServesStaleEndpoints(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, false)
	resp, _ := e.get(t, c, "/", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// The cached discovery result expires while the IdP is down: logins
	// keep using the endpoints already known instead of failing.
	e.login.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	e.idp.Server.Close()
	resp, _ = e.get(t, c, "/", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), e.idp.AuthorizeURL()))
}

// setIDCookie replaces the ID token cookie in c's jar with value, as if the
// browser still held a token the proxy no longer accepts.
func (e *loginEnv) setIDCookie(t *testing.T, c *http.Client, value string) {
	t.Helper()
	u, err := url.Parse(e.server.URL)
	require.NoError(t, err)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "tap_id_token", Value: value, Path: "/", MaxAge: 3600}})
}

func TestStale_ExpiredByServerClockIsRenewed(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, rotate: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)

	// The browser still holds the cookie (its clock is behind), but the
	// token inside has expired by the proxy's clock.
	e.setIDCookie(t, c, e.idp.MintLoginToken(t, loginClientID, -time.Minute, nil))
	before := e.idp.RefreshCalls()

	resp, body := e.get(t, c, "/api/x", map[string]string{"Accept": "application/json"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/api/x", body)
	assert.Equal(t, before+1, e.idp.RefreshCalls())

	resp, _ = e.get(t, c, "/api/y", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, before+1, e.idp.RefreshCalls(), "the renewed cookie replaced the stale one")
}

func TestStale_SignedByUnknownKeyIsRenewed(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true, rotate: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)

	// What a cookie signed by a key the IdP no longer publishes looks like.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := jwt.MapClaims{"iss": e.idp.Issuer, "aud": loginClientID, "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}
	e.setIDCookie(t, c, e.idp.SignWith(t, jwt.SigningMethodRS256, key, claims))

	resp, body := e.get(t, c, "/p", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend:/p", body)
	assert.Equal(t, 1, e.idp.RefreshCalls(), "the rejected cookie was renewed, not accepted")
}

func TestStale_GarbageCookieWithoutRefreshFallsBackToLogin(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, false)
	e.setIDCookie(t, c, "not.a.jwt")

	// A browser goes through login again instead of getting stuck on 401...
	resp, _ := e.get(t, c, "/page", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), e.idp.AuthorizeURL()))
	var cleared bool
	for _, ck := range resp.Cookies() {
		if ck.Name == "tap_id_token" && ck.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "the stale cookie is deleted from the browser")

	// ...and an API client gets the plain 401.
	e.setIDCookie(t, c, "not.a.jwt")
	resp, _ = e.get(t, c, "/api", map[string]string{"Accept": "application/json"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Zero(t, e.backend.Load())
}

func TestStale_BearerHeaderStillGets401(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	before := e.idp.RefreshCalls()

	// A token presented on purpose is a client error, not a session to
	// renew, even when a valid login cookie rides along.
	bad := e.idp.MintLoginToken(t, loginClientID, -time.Minute, nil)
	resp, _ := e.get(t, e.client(t, false), "/", map[string]string{"Authorization": "Bearer " + bad, "Accept": "application/json"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, before, e.idp.RefreshCalls())
}

func TestStale_OtherSourcesCookieIsKept(t *testing.T) {
	e := newLoginEnv(t, loginOpts{refresh: true})
	c := e.client(t, true)
	e.get(t, c, "/", nil)
	e.expireSession(t, c)
	e.setIDCookie(t, c, "garbage")
	u, _ := url.Parse(e.server.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "unrelated", Value: "keep", Path: "/", MaxAge: 3600}})

	resp, _ := e.get(t, c, "/", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("X-Seen-Cookies"), "unrelated", "only the stale login cookie is removed from the request")
}

func TestPicker_EmbeddedFont(t *testing.T) {
	e := newLoginEnv(t, loginOpts{basic: true})
	c := e.client(t, false)

	// The built-in styles use the embedded font.
	_, body := e.get(t, c, "/_tap/login", nil)
	assert.Contains(t, body, `font-family: "Schibsted Grotesk Variable"`)
	assert.Contains(t, body, `url("/_tap/login/font.woff2")`)

	// The font itself is served without a credential, and cached.
	resp, font := e.get(t, c, "/_tap/login/font.woff2", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "font/woff2", resp.Header.Get("Content-Type"))
	assert.Contains(t, resp.Header.Get("Cache-Control"), "immutable")
	assert.Equal(t, "wOF2", font[:4])
	assert.Zero(t, e.backend.Load())
}
