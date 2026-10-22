package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// deletedCookies returns the names of the cookies a response expires.
func deletedCookies(cookies []*http.Cookie) map[string]bool {
	out := map[string]bool{}
	for _, c := range cookies {
		if c.MaxAge < 0 {
			out[c.Name] = true
		}
	}
	return out
}

func TestLogout_ClearsTheSessionAndSendsTheBrowserBack(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, true)
	resp, _ := e.get(t, c, "/dash", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, cookieNames(c, e.server.URL), "tap_id_token")

	noFollow := e.client(t, false)
	noFollow.Jar = c.Jar
	resp, _ = e.get(t, noFollow, "/_tap/logout", nil)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	deleted := deletedCookies(resp.Cookies())
	assert.True(t, deleted["tap_id_token"], "the ID token cookie must be cleared")
	assert.True(t, deleted["tap_id_token_refresh"], "the refresh cookie must be cleared whether or not one was issued")
	assert.True(t, deleted[loginMethodCookie], "the remembered sign-in method must be cleared")
	assert.NotContains(t, cookieNames(c, e.server.URL), "tap_id_token")

	// Signed out: a browser navigation goes to the sign-in page again.
	resp, _ = e.get(t, noFollow, "/dash", nil)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/authorize?", "signed out, so the lone login method starts again")
}

func TestLogout_ReturnTo(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	c := e.client(t, false)
	for name, tc := range map[string]struct{ query, want string }{
		"a same-origin path is honored": {"?return_to=%2Fdocs%2F", "/docs/"},
		"an external URL is dropped":    {"?return_to=https%3A%2F%2Fevil.example.com", "/"},
		"a protocol-relative URL":       {"?return_to=%2F%2Fevil.example.com", "/"},
		"the logout route itself":       {"?return_to=%2F_tap%2Flogout", "/"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, _ := e.get(t, c, "/_tap/logout"+tc.query, nil)
			assert.Equal(t, http.StatusFound, resp.StatusCode)
			assert.Equal(t, tc.want, resp.Header.Get("Location"))
		})
	}
}

func TestLogout_MethodNotAllowed(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, e.server.URL+"/_tap/logout", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, "GET, HEAD, POST", resp.Header.Get("Allow"))
}

func TestLogout_EndSessionRedirectsToTheProviderWithTheIDToken(t *testing.T) {
	e := newLoginEnv(t, loginOpts{endSession: true, postLogoutURI: "https://proxy.example.com/_tap/login"})
	c := e.client(t, true)
	resp, _ := e.get(t, c, "/dash", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	serverURL, err := url.Parse(e.server.URL)
	require.NoError(t, err)
	var idToken string
	for _, ck := range c.Jar.Cookies(serverURL) {
		if ck.Name == "tap_id_token" {
			idToken = ck.Value
		}
	}
	require.NotEmpty(t, idToken)

	noFollow := e.client(t, false)
	noFollow.Jar = c.Jar
	resp, _ = e.get(t, noFollow, "/_tap/logout?return_to=%2Fdocs%2F", nil)

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	target, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, e.endSessionURL, target.Scheme+"://"+target.Host+target.Path)
	assert.Equal(t, idToken, target.Query().Get("id_token_hint"))
	assert.Equal(t, "https://proxy.example.com/_tap/login", target.Query().Get("post_logout_redirect_uri"))
	assert.True(t, deletedCookies(resp.Cookies())["tap_id_token"], "the cookies are cleared before the browser leaves")
}

func TestLogout_EndSessionStaysLocalWithoutAnIDTokenOrAnEndpoint(t *testing.T) {
	t.Run("not signed in", func(t *testing.T) {
		e := newLoginEnv(t, loginOpts{endSession: true})
		resp, _ := e.get(t, e.client(t, false), "/_tap/logout", nil)
		assert.Equal(t, "/", resp.Header.Get("Location"))
	})
	t.Run("the provider advertises no end_session_endpoint", func(t *testing.T) {
		e := newLoginEnv(t, loginOpts{endSession: true, noEndpoint: true})
		c := e.client(t, true)
		resp, _ := e.get(t, c, "/dash", nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		noFollow := e.client(t, false)
		noFollow.Jar = c.Jar
		resp, _ = e.get(t, noFollow, "/_tap/logout?return_to=%2Fdocs%2F", nil)
		assert.Equal(t, "/docs/", resp.Header.Get("Location"))
		assert.True(t, deletedCookies(resp.Cookies())["tap_id_token"])
	})
}

func TestLogout_ClearsTheSAMLSessionCookie(t *testing.T) {
	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	l := NewLoginRegistry(NewRegistry(testLogger()), testLogger())

	rr := httptest.NewRecorder()
	l.serveLogout(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_tap/logout", nil), cfg, testLogger())

	assert.Equal(t, http.StatusFound, rr.Code)
	deleted := deletedCookies(rr.Result().Cookies())
	assert.True(t, deleted[src.SessionCookie], "the SAML session cookie must be cleared")
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == src.SessionCookie {
			assert.Equal(t, "/", ck.Path)
			assert.True(t, ck.Secure, "sp_base_url is https, so the deleting cookie is Secure too")
		}
	}
}

func TestLogout_IsNotClaimedWithoutAnInteractiveMethod(t *testing.T) {
	e := newLoginEnv(t, loginOpts{})
	cfg := e.source.Current()
	assert.Positive(t, cfg.Inbound.Auth.LoginMethodCount())
	assert.True(t, isLogoutRoute(config.LogoutPath))
	assert.False(t, isLogoutRoute("/_tap/logout/other"))
}
