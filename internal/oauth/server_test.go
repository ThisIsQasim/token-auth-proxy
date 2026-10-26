package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const redirectURI = "http://localhost:8765/callback" // registered as http://localhost/callback

func newPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newSealKey(t *testing.T) string { return base64.StdEncoding.EncodeToString(testKey(t)) }

type signKeyCfg struct{ KID, PEM string }

// env is a running OAuth server behind a fake login: authenticate answers
// with who (and allowed) the way the proxy's own login would.
type env struct {
	t        *testing.T
	srv      *httptest.Server
	reg      *Registry
	cli      *http.Client
	base     string
	signing  []signKeyCfg
	sealing  []string
	denylist []string
	disabled bool

	who     Identity
	allowed bool
	respond func(w http.ResponseWriter, r *http.Request) // when set, the login responds itself
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t:       t,
		signing: []signKeyCfg{{"k1", newPEM(t)}},
		sealing: []string{newSealKey(t)},
		who: Identity{Mode: "saml", Claims: map[string]any{
			"sub": "alice", "email": "alice@example.com", "groups": []string{"os-mcp-readers"},
		}},
		allowed: true,
	}
	e.reg = NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mux := http.NewServeMux()
	mux.HandleFunc(config.OAuthPathPrefix+"/login", func(w http.ResponseWriter, r *http.Request) {
		e.reg.ServeLogin(w, r, func(w http.ResponseWriter, r *http.Request, allow func(Identity)) {
			if e.respond != nil {
				e.respond(w, r)
				return
			}
			allow(e.who)
		}, func(string, string, []string) bool { return e.allowed })
	})
	mux.Handle(config.OAuthPathPrefix+"/", e.reg)
	mux.HandleFunc("/.well-known/", func(w http.ResponseWriter, r *http.Request) {
		if e.reg.Serves(r.URL.Path) {
			e.reg.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	e.base = e.srv.URL
	e.cli = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	e.reload()
	return e
}

// config builds a validated Config the way an operator's flags would.
func (e *env) config() *config.Config {
	e.t.Helper()
	type sk struct {
		KID string `json:"kid"`
		Key string `json:"private_key"`
	}
	var keys []sk
	for _, k := range e.signing {
		keys = append(keys, sk{k.KID, k.PEM})
	}
	srvJSON, err := json.Marshal(map[string]any{
		"disabled": e.disabled, "sp_base_url": e.base, "mcp_url": e.base + "/mcp", "sealing_keys": e.sealing,
		"clients": []map[string]any{
			{"id": "claude-code", "redirect_uris": []string{"http://localhost/callback"}},
			{"id": "claude-ai", "redirect_uris": []string{"https://claude.ai/api/mcp/auth_callback"}},
		},
		"denylist": map[string]any{"subjects": e.denylist},
	})
	require.NoError(e.t, err)
	tokJSON, err := json.Marshal(map[string]any{"signing_keys": keys})
	require.NoError(e.t, err)
	// The OAuth server needs some way for people to log in; this one is never used
	// (the tests stand in for the login with env.authenticate).
	loginJSON, err := json.Marshal([]map[string]any{{
		"issuer": "https://idp.example.com", "oidc_discovery_url": "https://idp.example.com/.well-known/openid-configuration",
		"login": map[string]any{"client_id": "proxy", "sp_base_url": e.base},
	}})
	require.NoError(e.t, err)

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	require.NoError(e.t, fs.Parse([]string{
		"--target", "http://backend:9200",
		"--inbound-oauth-server-json", string(srvJSON),
		"--outbound-token-json", string(tokJSON),
		"--inbound-auth-jwt-json", string(loginJSON),
	}))
	src, err := config.Resolve(fs)
	require.NoError(e.t, err)
	return src.Config
}

// reload applies the env's current settings, like a config hot-reload.
func (e *env) reload() { e.reg.Reconcile(e.config()) }

func newPKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *env) issuer() string { return e.base + config.OAuthPathPrefix }

// reply is a response whose body has been read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// do sends a request and reads the whole reply; a non-nil form is posted.
func (e *env) do(method, u string, form url.Values) *reply {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(e.t.Context(), method, u, body)
	require.NoError(e.t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.cli.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	return &reply{StatusCode: resp.StatusCode, Header: resp.Header, Body: raw}
}

func (e *env) get(u string) *reply { return e.do(http.MethodGet, u, nil) }

func (e *env) authorizeURL(redirect, challenge string) string {
	return e.authorizeURLFor("claude-code", redirect, challenge)
}

func (e *env) authorizeURLFor(clientID, redirect, challenge string) string {
	return e.issuer() + "/authorize?" + url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid offline_access groups"}, "state": {"st123"}, "nonce": {"n1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
}

// authorize follows /authorize through the login to the client's redirect
// and returns the code, or the last response when the flow stops short.
func (e *env) authorize(redirect, challenge string) (code string, last *reply) {
	e.t.Helper()
	return e.authorizeAs("claude-code", redirect, challenge)
}

func (e *env) authorizeAs(clientID, redirect, challenge string) (code string, last *reply) {
	e.t.Helper()
	next := e.authorizeURLFor(clientID, redirect, challenge)
	for range 6 {
		resp := e.get(next)
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || loc == "" {
			return "", resp
		}
		if strings.HasPrefix(loc, redirect) {
			u, err := url.Parse(loc)
			require.NoError(e.t, err)
			require.Equal(e.t, "st123", u.Query().Get("state"), "the client's state comes back")
			return u.Query().Get("code"), resp
		}
		if !strings.HasPrefix(loc, e.base) {
			return "", resp // off to the identity provider or somewhere else: the flow stops here
		}
		next = loc
	}
	e.t.Fatal("too many redirects")
	return "", nil
}

func (e *env) token(form url.Values) (int, map[string]any) {
	e.t.Helper()
	resp := e.do(http.MethodPost, e.issuer()+"/token", form)
	var out map[string]any
	require.NoError(e.t, json.Unmarshal(resp.Body, &out))
	return resp.StatusCode, out
}

func (e *env) exchange(code, verifier string) (int, map[string]any) {
	return e.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {"claude-code"}, "code_verifier": {verifier},
	})
}

func (e *env) refresh(refreshToken string) (int, map[string]any) {
	return e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {"claude-code"}})
}

// login runs a whole successful authorization and returns the token response.
func (e *env) login() map[string]any {
	e.t.Helper()
	verifier, challenge := newPKCE()
	code, last := e.authorize(redirectURI, challenge)
	require.NotEmpty(e.t, code, "no code: status %d", last.StatusCode)
	status, tok := e.exchange(code, verifier)
	require.Equal(e.t, http.StatusOK, status, "%v", tok)
	return tok
}

// verify parses an access token the way the JWT leg would.
func (e *env) verify(access string) (*jwt.Token, jwt.MapClaims) {
	e.t.Helper()
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(access, claims, e.reg.Keyfunc(),
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(e.issuer()), jwt.WithAudience(e.base+"/mcp"), jwt.WithExpirationRequired())
	require.NoError(e.t, err)
	return tok, claims
}

func TestFlow_CodeAndRefresh(t *testing.T) {
	e := newEnv(t)
	tok := e.login()

	access := tok["access_token"].(string)
	parsed, claims := e.verify(access)
	assert.Equal(t, "k1", parsed.Header["kid"])
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Equal(t, []any{"os-mcp-readers"}, claims["groups"])
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), exp.Time, 5*time.Second)

	refresh := tok["refresh_token"].(string)
	require.NotEmpty(t, refresh)

	status, again := e.refresh(refresh)
	require.Equal(t, http.StatusOK, status, "%v", again)
	_, claims = e.verify(again["access_token"].(string))
	assert.Equal(t, []any{"os-mcp-readers"}, claims["groups"], "refreshing keeps the groups of the login")
	assert.NotEqual(t, refresh, again["refresh_token"], "a refresh issues a new refresh token")

	status, third := e.refresh(again["refresh_token"].(string))
	assert.Equal(t, http.StatusOK, status, "%v", third)
}

func TestFlow_RefreshLifetimeIsAbsolute(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	refresh := tok["refresh_token"].(string)

	st := e.reg.srv.Load().storage
	st.now = func() time.Time { return time.Now().Add(23 * time.Hour) }
	status, again := e.refresh(refresh)
	require.Equal(t, http.StatusOK, status, "%v", again)

	st.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	status, _ = e.refresh(again["refresh_token"].(string))
	assert.Equal(t, http.StatusBadRequest, status, "the lifetime counts from the login and refreshing does not extend it")
}

func TestFlow_PKCE(t *testing.T) {
	e := newEnv(t)
	verifier, challenge := newPKCE()
	code, _ := e.authorize(redirectURI, challenge)
	require.NotEmpty(t, code)

	other, _ := newPKCE()
	status, body := e.exchange(code, other)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	status, _ = e.exchange(code, verifier)
	assert.Equal(t, http.StatusOK, status, "the right verifier works; a code is not single use, PKCE and its short life are the protection")
}

func TestFlow_RedirectURIs(t *testing.T) {
	e := newEnv(t)
	_, challenge := newPKCE()

	for _, redirect := range []string{"http://localhost:1/callback", "http://localhost:54321/callback"} {
		code, last := e.authorize(redirect, challenge)
		assert.NotEmpty(t, code, "loopback matches on any port: %s (status %d)", redirect, last.StatusCode)
	}
	for _, redirect := range []string{"http://evil.example.com/callback", "http://localhost/other", "https://localhost/callback", "http://127.0.0.1/callback", "http://[::1]/callback", "http://localhost/callback?x=1", "http://user@localhost/callback"} {
		code, last := e.authorize(redirect, challenge)
		assert.Empty(t, code, redirect)
		assert.Equal(t, http.StatusBadRequest, last.StatusCode, "an unregistered redirect gets an error page, never a redirect: %s", redirect)
	}
}

func TestFlow_UnknownClient(t *testing.T) {
	e := newEnv(t)
	_, challenge := newPKCE()
	resp := e.get(strings.Replace(e.authorizeURL(redirectURI, challenge), "claude-code", "nobody", 1))
	assert.NotEqual(t, http.StatusFound, resp.StatusCode)
}

func TestFlow_PKCERequired(t *testing.T) {
	e := newEnv(t)
	u := e.issuer() + "/authorize?" + url.Values{
		"client_id": {"claude-code"}, "response_type": {"code"}, "redirect_uri": {redirectURI}, "scope": {"openid"},
	}.Encode()
	resp := e.get(u)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.NotContains(t, loc, "login?id=", "a request with no PKCE challenge must not reach the login")
	assert.Contains(t, loc, "error=invalid_request")

	_, challenge := newPKCE()
	plain := e.get(u + "&" + url.Values{"code_challenge": {challenge}, "code_challenge_method": {"plain"}}.Encode())
	assert.NotContains(t, plain.Header.Get("Location"), "login?id=", "plain PKCE is not accepted")
}

func TestLogin_Rejections(t *testing.T) {
	_, challenge := newPKCE()

	t.Run("denied by the acl", func(t *testing.T) {
		e := newEnv(t)
		e.allowed = false
		code, last := e.authorize(redirectURI, challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusForbidden, last.StatusCode)
	})
	t.Run("on the denylist", func(t *testing.T) {
		e := newEnv(t)
		e.denylist = []string{"alice"}
		e.reload()
		code, last := e.authorize(redirectURI, challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusForbidden, last.StatusCode)
	})
	t.Run("no subject", func(t *testing.T) {
		e := newEnv(t)
		e.who = Identity{Mode: "jwt", Claims: map[string]any{"email": "a@b"}}
		code, last := e.authorize(redirectURI, challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusForbidden, last.StatusCode)
	})
	t.Run("the login answers itself", func(t *testing.T) {
		e := newEnv(t)
		e.respond = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://idp.example.com/sso", http.StatusFound)
		}
		code, last := e.authorize(redirectURI, challenge)
		assert.Empty(t, code)
		assert.Equal(t, "https://idp.example.com/sso", last.Header.Get("Location"), "nothing is issued until the person is identified")
	})
	t.Run("the response is not cacheable", func(t *testing.T) {
		e := newEnv(t)
		resp := e.get(e.issuer() + "/login?id=x")
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	})
}

func TestLogin_RejectsBadLoginRequests(t *testing.T) {
	e := newEnv(t)
	s := e.reg.srv.Load()
	_, challenge := newPKCE()

	sealed := func(kind string, d reqData) string {
		tok, err := s.sealer.seal(kind, d)
		require.NoError(t, err)
		return tok
	}
	valid := reqData{ClientID: "claude-code", RedirectURI: redirectURI, Challenge: challenge, Method: "S256", Exp: time.Now().Add(time.Minute).Unix()}
	refresh, err := s.sealer.seal(kindRefresh, refreshData{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	pending := sealed(kindPending, valid)

	for name, id := range map[string]string{
		"missing":       "",
		"garbage":       "nope",
		"tampered":      pending[:len(pending)-3] + "AAA",
		"expired":       sealed(kindPending, reqData{ClientID: "claude-code", Exp: time.Now().Add(-time.Second).Unix()}),
		"already done":  sealed(kindDone, valid),
		"refresh token": refresh,
	} {
		t.Run(name, func(t *testing.T) {
			resp := e.get(e.issuer() + "/login?id=" + url.QueryEscape(id))
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}

	resp := e.get(e.issuer() + "/login?id=" + url.QueryEscape(pending))
	assert.Equal(t, http.StatusFound, resp.StatusCode, "a valid pending request logs in")
	assert.Contains(t, resp.Header.Get("Location"), "/authorize/callback?id=")

	post := e.do(http.MethodPost, e.issuer()+"/login?id="+url.QueryEscape(pending), url.Values{})
	assert.Equal(t, http.StatusMethodNotAllowed, post.StatusCode)
}

func TestCallback_DoesNotTrustWhatIsNotALogin(t *testing.T) {
	e := newEnv(t)
	s := e.reg.srv.Load()
	_, challenge := newPKCE()

	refresh, err := s.sealer.seal(kindRefresh, refreshData{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	resp := e.get(e.issuer() + "/authorize/callback?id=" + url.QueryEscape(refresh))
	assert.NotContains(t, resp.Header.Get("Location"), "code=", "a refresh token is not a login")

	// A request the client made but nobody logged in for must not become a code.
	resp = e.get(e.authorizeURL(redirectURI, challenge))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	pending := u.Query().Get("id")
	require.NotEmpty(t, pending)

	resp = e.get(e.issuer() + "/authorize/callback?id=" + url.QueryEscape(pending))
	assert.NotContains(t, resp.Header.Get("Location"), "code=")
	assert.Contains(t, resp.Header.Get("Location"), "error=interaction_required")
}

func TestCode_ExpiresWithTheLogin(t *testing.T) {
	e := newEnv(t)
	verifier, challenge := newPKCE()
	code, _ := e.authorize(redirectURI, challenge)
	require.NotEmpty(t, code)

	e.reg.srv.Load().storage.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	status, body := e.exchange(code, verifier)
	assert.Equal(t, http.StatusBadRequest, status, "%v", body)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestDenylist_AppliesWithoutARebuild(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	refresh := tok["refresh_token"].(string)
	built := e.reg.srv.Load()
	assert.False(t, e.reg.Denied("alice"))

	e.denylist = []string{"alice"}
	e.reload()
	assert.Same(t, built, e.reg.srv.Load(), "the denylist is read live; nothing is rebuilt")
	assert.True(t, e.reg.Denied("alice"))
	assert.False(t, e.reg.Denied("bob"))

	status, body := e.refresh(refresh)
	assert.Equal(t, http.StatusBadRequest, status, "%v", body)
	_, last := e.authorize(redirectURI, mustChallenge())
	assert.Equal(t, http.StatusForbidden, last.StatusCode)

	e.denylist = nil
	e.reload()
	status, _ = e.refresh(refresh)
	assert.Equal(t, http.StatusOK, status, "taking the subject off the list restores access")
}

func mustChallenge() string { _, c := newPKCE(); return c }

func TestKeyRotation(t *testing.T) {
	e := newEnv(t)
	old := e.login()
	oldAccess := old["access_token"].(string)
	oldRefresh := old["refresh_token"].(string)
	before := e.reg.srv.Load()

	e.signing = []signKeyCfg{{"k2", newPEM(t)}, e.signing[0]}
	e.reload()
	assert.NotSame(t, before, e.reg.srv.Load(), "new keys rebuild the server")

	e.verify(oldAccess) // still verifies: the old key stays listed
	status, again := e.refresh(oldRefresh)
	require.Equal(t, http.StatusOK, status, "%v", again)
	parsed, _ := e.verify(again["access_token"].(string))
	assert.Equal(t, "k2", parsed.Header["kid"], "the first key signs")

	resp := e.get(e.issuer() + "/jwks.json")
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &jwks))
	var kids []string
	for _, k := range jwks.Keys {
		kids = append(kids, k.Kid)
		assert.Equal(t, "ES256", k.Alg)
	}
	assert.ElementsMatch(t, []string{"k1", "k2"}, kids)

	e.signing = e.signing[:1] // the old key is finally dropped
	e.reload()
	_, err := jwt.Parse(oldAccess, e.reg.Keyfunc(), jwt.WithValidMethods([]string{"ES256"}))
	assert.Error(t, err, "tokens of a dropped key no longer verify")
}

func TestSealingKeyRotation(t *testing.T) {
	e := newEnv(t)
	tok := e.login()
	refresh := tok["refresh_token"].(string)

	e.sealing = []string{newSealKey(t), e.sealing[0]}
	e.reload()
	status, again := e.refresh(refresh)
	require.Equal(t, http.StatusOK, status, "a refresh token sealed under the previous key still works: %v", again)

	e.sealing = e.sealing[:1]
	e.reload()
	status, _ = e.refresh(again["refresh_token"].(string))
	assert.Equal(t, http.StatusOK, status, "what was sealed under the new key keeps working")
	status, _ = e.refresh(refresh)
	assert.Equal(t, http.StatusBadRequest, status, "but what the dropped key sealed does not")
}

func TestDiscoveryAndMetadata(t *testing.T) {
	e := newEnv(t)

	resp := e.get(e.issuer() + "/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &doc))
	assert.Equal(t, e.issuer(), doc["issuer"])
	assert.Equal(t, e.issuer()+"/authorize", doc["authorization_endpoint"])
	assert.Equal(t, e.issuer()+"/token", doc["token_endpoint"])
	assert.Equal(t, e.issuer()+"/jwks.json", doc["jwks_uri"])
	assert.Equal(t, []any{"S256"}, doc["code_challenge_methods_supported"])

	resp = e.get(e.issuer() + "/protected-resource")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	var meta map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &meta))
	assert.Equal(t, e.base+"/mcp", meta["resource"])
	assert.Equal(t, []any{e.issuer()}, meta["authorization_servers"])
	assert.Contains(t, meta["scopes_supported"], "offline_access")
}

func TestDisabled(t *testing.T) {
	e := newEnv(t)
	require.True(t, e.reg.Enabled())
	tok := e.login()

	e.disabled = true
	e.reload()
	assert.False(t, e.reg.Enabled())
	assert.Equal(t, http.StatusNotFound, e.get(e.issuer()+"/.well-known/openid-configuration").StatusCode)
	assert.Equal(t, http.StatusNotFound, e.get(e.issuer()+"/login?id=x").StatusCode)
	_, err := jwt.Parse(tok["access_token"].(string), e.reg.Keyfunc(), jwt.WithValidMethods([]string{"ES256"}))
	assert.Error(t, err, "nothing verifies while the server is off")
	assert.True(t, e.reg.Denied("anyone"), "and everyone is denied")

	e.disabled = false
	e.reload()
	assert.True(t, e.reg.Enabled(), "turning it back on rebuilds it")
}

func TestRegistry_ReconcileIsIdempotent(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	e.reg.Reconcile(cfg)
	built := e.reg.srv.Load()
	e.reg.Reconcile(cfg)
	e.reg.Reconcile(e.config()) // an equal config, as a reload with no change produces
	assert.Same(t, built, e.reg.srv.Load())
}

func TestRoutes_OnlyWhatIsSupported(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/revoke", "/userinfo", "/end_session", "/oauth/introspect", "/introspect", "/device_authorization", "/healthz", "/ready", "/nope", "/jwks"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			r := e.do(method, e.issuer()+path, url.Values{"token": {"x"}})
			assert.Equal(t, http.StatusNotFound, r.StatusCode, "%s %s is not something this server does", method, path)
		}
	}
	assert.Equal(t, http.StatusOK, e.get(e.issuer()+"/jwks.json").StatusCode)
}

func TestDiscovery_ListsOnlyWhatWorks(t *testing.T) {
	e := newEnv(t)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(e.get(e.issuer()+"/.well-known/openid-configuration").Body, &doc))

	for _, gone := range []string{
		"introspection_endpoint", "userinfo_endpoint", "revocation_endpoint", "end_session_endpoint",
		"device_authorization_endpoint", "check_session_iframe", "revocation_endpoint_auth_methods_supported",
		"introspection_endpoint_auth_methods_supported",
	} {
		assert.NotContains(t, doc, gone, "not advertised: it would not work")
	}
	assert.Equal(t, []any{"authorization_code", "refresh_token"}, doc["grant_types_supported"])
	assert.Equal(t, []any{"none"}, doc["token_endpoint_auth_methods_supported"], "public clients only")
	assert.Equal(t, []any{"S256"}, doc["code_challenge_methods_supported"])
	assert.Equal(t, []any{"code"}, doc["response_types_supported"])
	assert.Equal(t, e.issuer()+"/authorize", doc["authorization_endpoint"])
}

func TestWellKnownAliases(t *testing.T) {
	e := newEnv(t)
	discovery := e.get(e.issuer() + "/.well-known/openid-configuration").Body
	resource := e.get(e.issuer() + "/protected-resource").Body

	for path, want := range map[string][]byte{
		"/.well-known/oauth-protected-resource":                            resource,
		"/.well-known/oauth-protected-resource/mcp":                        resource,
		"/.well-known/oauth-authorization-server" + config.OAuthPathPrefix: discovery,
		"/.well-known/openid-configuration" + config.OAuthPathPrefix:       discovery,
	} {
		r := e.get(e.base + path)
		assert.Equal(t, http.StatusOK, r.StatusCode, path)
		assert.JSONEq(t, string(want), string(r.Body), path)
		assert.True(t, e.reg.Serves(path), path)
	}

	for _, path := range []string{
		"/.well-known/oauth-authorization-server", // the issuer has a path: only its inserted form is its metadata
		"/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource/other",
		"/.well-known/security.txt",
		"/mcp",
	} {
		assert.False(t, e.reg.Serves(path), path)
		assert.Equal(t, http.StatusNotFound, e.get(e.base+path).StatusCode, path)
	}
	assert.True(t, e.reg.Serves(config.OAuthPathPrefix+"/login"))
	assert.True(t, e.reg.Serves(config.OAuthPathPrefix))
}

func TestServes_FalseWhileOff(t *testing.T) {
	e := newEnv(t)
	e.disabled = true
	e.reload()
	assert.False(t, e.reg.Serves(config.OAuthPathPrefix+"/token"))
	assert.False(t, e.reg.Serves("/.well-known/oauth-protected-resource"))
}

func TestFlow_OnlyTheCodeFlow(t *testing.T) {
	e := newEnv(t)
	_, challenge := newPKCE()
	for _, responseType := range []string{"token", "id_token", "id_token token", "code id_token"} {
		u := strings.Replace(e.authorizeURL(redirectURI, challenge), "response_type=code", "response_type="+url.QueryEscape(responseType), 1)
		resp := e.get(u)
		assert.NotContains(t, resp.Header.Get("Location"), "login?id=", "response_type=%s must not start a login", responseType)
	}

	status, body := e.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"claude-code"}})
	assert.NotEqual(t, http.StatusOK, status, "%v", body)
	status, body = e.token(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"claude-code"}, "device_code": {"x"}})
	assert.NotEqual(t, http.StatusOK, status, "%v", body)
}

func TestCode_RefusedOnceTheSubjectIsDenied(t *testing.T) {
	e := newEnv(t)
	verifier, challenge := newPKCE()
	code, _ := e.authorize(redirectURI, challenge)
	require.NotEmpty(t, code)

	e.denylist = []string{"alice"}
	e.reload()
	status, body := e.exchange(code, verifier)
	assert.Equal(t, http.StatusBadRequest, status, "a login finished just before the subject was listed gets no tokens: %v", body)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestLogin_OnlyGET(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.respond = func(w http.ResponseWriter, _ *http.Request) { calls++; http.Error(w, "login ran", http.StatusTeapot) }

	pending, err := e.reg.srv.Load().sealer.seal(kindPending, reqData{ClientID: "claude-code", Challenge: "c", Method: "S256", Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)
	u := e.issuer() + "/login?id=" + url.QueryEscape(pending)

	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := e.do(method, u, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, r.StatusCode, method)
	}
	assert.Zero(t, calls, "nothing but a GET reaches the login")
	assert.Equal(t, http.StatusTeapot, e.get(u).StatusCode)
	assert.Equal(t, 1, calls)
}

func TestDocs_CrossOrigin(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{
		e.issuer() + "/.well-known/openid-configuration", e.issuer() + "/protected-resource",
		e.base + "/.well-known/oauth-protected-resource", e.base + "/.well-known/oauth-authorization-server" + config.OAuthPathPrefix,
	} {
		get := e.get(path)
		assert.Equal(t, http.StatusOK, get.StatusCode, path)
		assert.Equal(t, "*", get.Header.Get("Access-Control-Allow-Origin"), path)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, path, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://inspector.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "mcp-protocol-version")
		resp, err := e.cli.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "the preflight is answered: %s", path)
		assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
		assert.Equal(t, "mcp-protocol-version", resp.Header.Get("Access-Control-Allow-Headers"))

		head := e.do(http.MethodHead, path, nil)
		assert.Equal(t, http.StatusOK, head.StatusCode)
		assert.Empty(t, head.Body, "HEAD has no body")
		assert.Equal(t, http.StatusMethodNotAllowed, e.do(http.MethodPost, path, url.Values{}).StatusCode, path)
	}
}

func TestTruncate_KeepsValidUTF8(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abc", truncate("abcdef", 3))
	got := truncate("ééé", 3) // each é is two bytes: the third byte would be half of the second
	assert.Equal(t, "é", got)
	assert.True(t, utf8.ValidString(got))
}

// claude.ai, Claude Desktop, mobile and Cowork connect as one public client with a
// fixed https callback, unlike Claude Code's loopback one.
func TestFlow_HostedClient(t *testing.T) {
	e := newEnv(t)
	const hosted = "https://claude.ai/api/mcp/auth_callback"
	verifier, challenge := newPKCE()

	code, last := e.authorizeAs("claude-ai", hosted, challenge)
	require.NotEmpty(t, code, "status %d", last.StatusCode)

	status, tok := e.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {hosted},
		"client_id": {"claude-ai"}, "code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, status, "%v", tok)
	_, claims := e.verify(tok["access_token"].(string))
	assert.Equal(t, "alice", claims["sub"])

	status, again := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"claude-ai"}})
	assert.Equal(t, http.StatusOK, status, "the hosted client refreshes too: %v", again)

	t.Run("only the registered callback", func(t *testing.T) {
		for _, redirect := range []string{
			"https://claude.ai/api/mcp/auth_callback/", "https://claude.ai/api/mcp/other", "https://claude.com/api/mcp/auth_callback",
			"http://claude.ai/api/mcp/auth_callback", "https://evil.example.com/api/mcp/auth_callback",
		} {
			code, last := e.authorizeAs("claude-ai", redirect, challenge)
			assert.Empty(t, code, redirect)
			assert.Equal(t, http.StatusBadRequest, last.StatusCode, redirect)
		}
	})
	t.Run("the clients do not share callbacks", func(t *testing.T) {
		code, _ := e.authorizeAs("claude-ai", redirectURI, challenge)
		assert.Empty(t, code, "the loopback callback is claude-code's, not claude-ai's")
		code, _ = e.authorizeAs("claude-code", hosted, challenge)
		assert.Empty(t, code, "and the hosted callback is not claude-code's")
	})
}
