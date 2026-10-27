package authn

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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/oauth"
)

const (
	mcpPath       = "/_plugins/_ml/mcp"
	oauthLoopback = "http://localhost:8765/callback"
)

// oauthMW is the whole proxy middleware with the OAuth server on, behind a
// real HTTP server, with Basic as the way to log in.
type oauthMW struct {
	t       *testing.T
	srv     *httptest.Server
	base    string
	backend *backendStub
	source  *fakeSource
	oauth   *oauth.Registry
	cli     *http.Client

	saml     *TestSAMLIDP // when set, SAML is the way to log in instead of Basic
	signKey  *ecdsa.PrivateKey
	signPEM  string
	sealKey  string
	denylist []string
	disabled bool
	dynamic  map[string]any // the dynamic_registration setting, nil for off
}

func newOAuthMW(t *testing.T) *oauthMW { return newOAuthMWWith(t, false) }

// newOAuthMWWith builds the harness, with SAML (a real test IdP) as the login
// when withSAML is set and Basic otherwise.
func newOAuthMWWith(t *testing.T, withSAML bool) *oauthMW {
	t.Helper()
	m := &oauthMW{t: t, backend: &backendStub{}}
	if withSAML {
		t.Setenv("OAUTH_MW_SAML_KEY", validSAMLSessionKeyForTest)
		m.saml = NewTestSAMLIDP(t)
	}

	m.signKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(m.signKey)
	require.NoError(t, err)
	m.signPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	seal := make([]byte, 32)
	_, _ = rand.Read(seal)
	m.sealKey = base64.StdEncoding.EncodeToString(seal)

	var handler http.Handler
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(m.srv.Close)
	m.base = m.srv.URL
	if m.saml != nil {
		m.saml.RegisterSP(m.base+"/saml/metadata", m.base+"/saml/acs")
		m.saml.SetUser("carol@example.com", map[string][]string{"groups": {"os-mcp-readers"}, "email": {"carol@example.com"}})
	}
	m.cli = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	m.source = newFakeSource(t, m.config())
	jwtReg := NewRegistry(testLogger())
	t.Cleanup(jwtReg.Close)
	samlReg := NewSAMLRegistry(testLogger())
	t.Cleanup(samlReg.Close)
	m.oauth = oauth.NewRegistry(testLogger())
	jwtReg.SetLocalSource(m.oauth.Keyfunc(), m.oauth.Denied)
	handler = NewMiddleware(m.source, jwtReg, samlReg, NewBasicRegistry(testLogger()), NewLoginRegistry(jwtReg, testLogger()), m.oauth, testLogger())(m.backend.Handler())
	return m
}

// config builds the validated Config an operator's flags would.
func (m *oauthMW) config() *config.Config {
	m.t.Helper()
	hash, err := sharedBasicHash() // "hunter2"
	require.NoError(m.t, err)
	mustJSON := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(m.t, err)
		return string(b)
	}
	login := []string{"--inbound-auth-basic-json", mustJSON(map[string]any{"users": []map[string]string{
		{"username": "alice", "password_hash": hash}, {"username": "bob", "password_hash": hash},
	}})}
	if m.saml != nil {
		login = []string{"--inbound-auth-saml-json", mustJSON(map[string]any{
			"issuer": m.saml.Issuer, "idp_metadata_url": m.saml.MetadataURL, "sp_base_url": m.base,
			"sp_entity_id": m.base + "/saml/metadata", "acs_path": "/saml/acs", "session_cookie": "saml_session",
			"session_signing_key_env": "OAUTH_MW_SAML_KEY", "session_duration": "1h",
		})}
	}
	server := map[string]any{
		"disabled": m.disabled, "sp_base_url": m.base, "mcp_url": m.base + mcpPath, "sealing_keys": []string{m.sealKey},
		"clients":  []map[string]any{{"id": "claude-code", "redirect_uris": []string{"http://localhost/callback"}}},
		"denylist": map[string]any{"subjects": m.denylist},
	}
	if m.dynamic != nil {
		server["dynamic_registration"] = m.dynamic
	}
	args := append([]string{"--target", "http://opensearch:9200"}, login...)
	args = append(args,
		"--inbound-oauth-server-json", mustJSON(server),
		"--outbound-token-json", mustJSON(map[string]any{"signing_keys": []map[string]string{{"kid": "k1", "private_key": m.signPEM}}}),
		// The MCP endpoint is for readers (by group) and for alice (by name, which is
		// how a Basic login shows up); bob is neither.
		"--acl-json", mustJSON([]map[string]any{
			{"principals": []map[string]any{{"mode": "jwt", "source": config.OAuthSourceName, "claims": map[string]string{"groups": "os-mcp-readers"}}}, "paths": []string{mcpPath}},
			{"principals": []map[string]any{{"mode": "jwt", "source": config.OAuthSourceName, "claims": map[string]string{"sub": "alice"}}}, "paths": []string{mcpPath}},
		}),
	)
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	require.NoError(m.t, fs.Parse(args))
	src, err := config.Resolve(fs)
	require.NoError(m.t, err)
	return src.Config
}

func (m *oauthMW) reload()        { m.source.set(m.config()) }
func (m *oauthMW) issuer() string { return m.base + config.OAuthPathPrefix }

// send makes a request, reads the reply and closes the body.
type mwReply struct {
	Code    int
	Header  http.Header
	Body    string
	Cookies []*http.Cookie
}

// cookie returns the cookie set by the reply whose name starts with prefix.
func (r *mwReply) cookie(prefix string) *http.Cookie {
	for _, c := range r.Cookies {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	return nil
}

func (m *oauthMW) send(method, target string, header map[string]string, form url.Values) *mwReply {
	m.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(m.t.Context(), method, target, body)
	require.NoError(m.t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := m.cli.Do(req)
	require.NoError(m.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(m.t, err)
	return &mwReply{Code: resp.StatusCode, Header: resp.Header, Body: string(raw), Cookies: resp.Cookies()}
}

func basicAuth(user string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":hunter2"))}
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

// mint signs a token the way the OAuth server does, with claims of the test's choosing.
func (m *oauthMW) mint(mutate func(jwt.MapClaims), method jwt.SigningMethod, key any) string {
	m.t.Helper()
	claims := jwt.MapClaims{
		"iss": m.issuer(), "aud": []string{m.base + mcpPath}, "sub": "carol", "groups": []string{"os-mcp-readers"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	require.NoError(m.t, err)
	return signed
}

func (m *oauthMW) validToken() string { return m.mint(nil, jwt.SigningMethodES256, m.signKey) }

func TestOAuthMW_ServerRoutesNeedNoCredential(t *testing.T) {
	m := newOAuthMW(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/protected-resource", "/jwks.json"} {
		r := m.send(http.MethodGet, m.issuer()+path, nil, nil)
		assert.Equal(t, http.StatusOK, r.Code, path)
		assert.NotEqual(t, backendBody, r.Body, "served by the proxy, not the backend: %s", path)
	}
	// The same two documents at the locations a client that ignores the
	// resource_metadata hint looks in.
	for _, path := range []string{
		"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + mcpPath,
		"/.well-known/oauth-authorization-server" + config.OAuthPathPrefix, "/.well-known/openid-configuration" + config.OAuthPathPrefix,
	} {
		r := m.send(http.MethodGet, m.base+path, nil, nil)
		assert.Equal(t, http.StatusOK, r.Code, path)
		assert.NotEqual(t, backendBody, r.Body, path)
	}
	r := m.send(http.MethodGet, m.base+"/.well-known/oauth-authorization-server", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code, "only the documents of this server are open; any other path still needs a credential")
	assert.Zero(t, m.backend.Hits())

	var meta struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
	}
	r = m.send(http.MethodGet, m.issuer()+"/protected-resource", nil, nil)
	require.NoError(t, json.Unmarshal([]byte(r.Body), &meta))
	assert.Equal(t, m.base+mcpPath, meta.Resource)
	assert.Equal(t, []string{m.issuer()}, meta.Servers)
}

func TestOAuthMW_ChallengesNameTheMetadata(t *testing.T) {
	m := newOAuthMW(t)
	metadata := `resource_metadata="` + m.issuer() + `/protected-resource"`

	r := m.send(http.MethodGet, m.base+mcpPath, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code)
	assert.Contains(t, r.Header.Values("WWW-Authenticate"), "Bearer "+metadata, "a client with no token is told where to log in")

	r = m.send(http.MethodGet, m.base+mcpPath, bearer("not-a-token"), nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code)
	assert.Equal(t, []string{`Bearer error="invalid_token", ` + metadata}, r.Header.Values("WWW-Authenticate"))
	assert.Zero(t, m.backend.Hits())
}

func TestOAuthMW_IssuedTokens(t *testing.T) {
	m := newOAuthMW(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name   string
		header map[string]string
		path   string
		want   int
	}{
		{"valid, in the readers group", bearer(m.validToken()), mcpPath, http.StatusOK},
		{"valid, but not in the group", bearer(m.mint(func(c jwt.MapClaims) { c["groups"] = []string{"other"} }, jwt.SigningMethodES256, m.signKey)), mcpPath, http.StatusForbidden},
		{"valid, but another path", bearer(m.validToken()), "/_search", http.StatusForbidden},
		{"wrong audience", bearer(m.mint(func(c jwt.MapClaims) { c["aud"] = []string{"https://elsewhere.example.com"} }, jwt.SigningMethodES256, m.signKey)), mcpPath, http.StatusUnauthorized},
		{"wrong issuer", bearer(m.mint(func(c jwt.MapClaims) { c["iss"] = "https://idp.example.com" }, jwt.SigningMethodES256, m.signKey)), mcpPath, http.StatusUnauthorized},
		{"expired", bearer(m.mint(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, jwt.SigningMethodES256, m.signKey)), mcpPath, http.StatusUnauthorized},
		{"no expiry", bearer(m.mint(func(c jwt.MapClaims) { delete(c, "exp") }, jwt.SigningMethodES256, m.signKey)), mcpPath, http.StatusUnauthorized},
		{"signed by another key", bearer(m.mint(nil, jwt.SigningMethodES256, other)), mcpPath, http.StatusUnauthorized},
		{"HS256 with the public key as secret", bearer(m.mint(nil, jwt.SigningMethodHS256, []byte("secret"))), mcpPath, http.StatusUnauthorized},
		{"alg none", bearer(m.mint(nil, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)), mcpPath, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := m.backend.Hits()
			r := m.send(http.MethodPost, m.base+tt.path, tt.header, nil)
			assert.Equal(t, tt.want, r.Code)
			if tt.want == http.StatusOK {
				assert.Equal(t, backendBody, r.Body)
				assert.Equal(t, tt.header["Authorization"], m.backend.lastAuthValue.Load(), "the token is forwarded unchanged")
			} else {
				assert.Equal(t, before, m.backend.Hits(), "the backend must not be reached")
			}
		})
	}
}

func TestOAuthMW_DenylistCutsOffAnIssuedToken(t *testing.T) {
	m := newOAuthMW(t)
	token := m.validToken()
	assert.Equal(t, http.StatusOK, m.send(http.MethodPost, m.base+mcpPath, bearer(token), nil).Code)

	m.denylist = []string{"carol"}
	m.reload()
	r := m.send(http.MethodPost, m.base+mcpPath, bearer(token), nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code, "a valid token stops working the moment its subject is listed")
	assert.Equal(t, 1, m.backend.Hits())

	m.denylist = nil
	m.reload()
	assert.Equal(t, http.StatusOK, m.send(http.MethodPost, m.base+mcpPath, bearer(token), nil).Code)
}

// authorizeURL starts a login the way Claude Code does.
func (m *oauthMW) authorizeURL(challenge string) string {
	return m.issuer() + "/authorize?" + url.Values{
		"client_id": {"claude-code"}, "response_type": {"code"}, "redirect_uri": {oauthLoopback},
		"scope": {"openid offline_access"}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
}

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// loginAs drives /authorize, the login (authenticating with header) and the
// callback. It returns the code, or the reply that stopped the flow.
func (m *oauthMW) loginAs(header map[string]string, challenge string) (code string, stopped *mwReply) {
	m.t.Helper()
	r := m.send(http.MethodGet, m.authorizeURL(challenge), nil, nil)
	require.Equal(m.t, http.StatusFound, r.Code, r.Body)
	loginURL := r.Header.Get("Location")
	require.Contains(m.t, loginURL, config.OAuthPathPrefix+"/login?id=")

	r = m.send(http.MethodGet, loginURL, header, nil)
	if r.Code != http.StatusFound {
		return "", r
	}
	r = m.send(http.MethodGet, r.Header.Get("Location"), nil, nil)
	require.Equal(m.t, http.StatusFound, r.Code, r.Body)
	loc, err := url.Parse(r.Header.Get("Location"))
	require.NoError(m.t, err)
	require.True(m.t, strings.HasPrefix(r.Header.Get("Location"), oauthLoopback), r.Header.Get("Location"))
	return loc.Query().Get("code"), nil
}

func (m *oauthMW) exchange(code, verifier string) (int, map[string]any) {
	m.t.Helper()
	r := m.send(http.MethodPost, m.issuer()+"/token", nil, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oauthLoopback},
		"client_id": {"claude-code"}, "code_verifier": {verifier},
	})
	var out map[string]any
	require.NoError(m.t, json.Unmarshal([]byte(r.Body), &out))
	return r.Code, out
}

func TestOAuthMW_EndToEnd_BasicLogin(t *testing.T) {
	m := newOAuthMW(t)
	verifier, challenge := pkcePair()

	code, stopped := m.loginAs(basicAuth("alice"), challenge)
	require.Nil(t, stopped)
	status, tok := m.exchange(code, verifier)
	require.Equal(t, http.StatusOK, status, "%v", tok)
	access := tok["access_token"].(string)

	r := m.send(http.MethodPost, m.base+mcpPath, bearer(access), nil)
	assert.Equal(t, http.StatusOK, r.Code, "alice's token reaches the MCP endpoint")
	assert.Equal(t, backendBody, r.Body)
	assert.Equal(t, "Bearer "+access, m.backend.lastAuthValue.Load())

	r = m.send(http.MethodPost, m.base+"/_search", bearer(access), nil)
	assert.Equal(t, http.StatusForbidden, r.Code, "but nothing else: the ACL limits the token to the MCP path")

	r = m.send(http.MethodPost, m.issuer()+"/token", nil, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"claude-code"},
	})
	assert.Equal(t, http.StatusOK, r.Code, "and it refreshes through the proxy: %s", r.Body)
}

func TestOAuthMW_Login_Rejections(t *testing.T) {
	_, challenge := pkcePair()

	t.Run("no credential", func(t *testing.T) {
		m := newOAuthMW(t)
		code, stopped := m.loginAs(nil, challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusUnauthorized, stopped.Code, "a Basic login asks for the password")
		assert.Contains(t, strings.Join(stopped.Header.Values("WWW-Authenticate"), ","), "Basic")
	})
	t.Run("wrong password", func(t *testing.T) {
		m := newOAuthMW(t)
		code, stopped := m.loginAs(map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))}, challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusUnauthorized, stopped.Code)
	})
	t.Run("authenticated but the acl refuses their token", func(t *testing.T) {
		m := newOAuthMW(t)
		code, stopped := m.loginAs(basicAuth("bob"), challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusForbidden, stopped.Code, "bob could never use the token, so he gets none")
	})
	t.Run("denylisted", func(t *testing.T) {
		m := newOAuthMW(t)
		m.denylist = []string{"alice"}
		m.reload()
		code, stopped := m.loginAs(basicAuth("alice"), challenge)
		assert.Empty(t, code)
		assert.Equal(t, http.StatusForbidden, stopped.Code)
	})
	t.Run("an issued token is not a login", func(t *testing.T) {
		m := newOAuthMW(t)
		code, stopped := m.loginAs(bearer(m.validToken()), challenge)
		assert.Empty(t, code, "a stolen access token must not buy a new refresh token")
		require.NotNil(t, stopped)
		assert.Equal(t, http.StatusForbidden, stopped.Code)
	})
	t.Run("the request id is checked before the login", func(t *testing.T) {
		m := newOAuthMW(t)
		r := m.send(http.MethodGet, m.issuer()+"/login?id=forged", basicAuth("alice"), nil)
		assert.Equal(t, http.StatusBadRequest, r.Code)
	})
}

func TestOAuthMW_Disabled(t *testing.T) {
	m := newOAuthMW(t)
	m.disabled = true
	m.reload()

	r := m.send(http.MethodGet, m.issuer()+"/.well-known/openid-configuration", nil, nil)
	assert.NotEqual(t, http.StatusOK, r.Code, "a disabled server serves nothing")
	r = m.send(http.MethodPost, m.base+mcpPath, bearer(m.validToken()), nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code, "and its tokens are not accepted")
	assert.Zero(t, m.backend.Hits())
	assert.NotContains(t, strings.Join(r.Header.Values("WWW-Authenticate"), ","), "resource_metadata")
}

func cookieHeader(c *http.Cookie) map[string]string {
	return map[string]string{"Cookie": c.Name + "=" + c.Value}
}

// With SAML as the way to log in, an MCP client probing the protected URL must
// still be told where to log in. A redirect to the IdP is no use to it.
func TestOAuthMW_SAMLLogin(t *testing.T) {
	m := newOAuthMWWith(t, true)
	html := map[string]string{"Accept": "text/html"}
	metadata := `resource_metadata="` + m.issuer() + `/protected-resource"`

	t.Run("a client without a session gets the bearer challenge", func(t *testing.T) {
		r := m.send(http.MethodPost, m.base+mcpPath, nil, nil)
		assert.Equal(t, http.StatusUnauthorized, r.Code)
		assert.Contains(t, r.Header.Values("WWW-Authenticate"), "Bearer "+metadata)
		assert.Empty(t, r.Header.Get("Location"), "no redirect to the IdP")
		assert.Zero(t, m.backend.Hits())
	})
	t.Run("a browser is still sent to the IdP", func(t *testing.T) {
		r := m.send(http.MethodGet, m.base+mcpPath, html, nil)
		assert.Equal(t, http.StatusFound, r.Code)
		assert.Contains(t, r.Header.Get("Location"), "SAMLRequest=")
	})

	t.Run("logging in through SAML gives a token with the person's groups", func(t *testing.T) {
		verifier, challenge := pkcePair()
		r := m.send(http.MethodGet, m.authorizeURL(challenge), nil, nil)
		require.Equal(t, http.StatusFound, r.Code, r.Body)
		loginURL := r.Header.Get("Location")

		// The browser follows the login to the IdP, which authenticates the person.
		r = m.send(http.MethodGet, loginURL, html, nil)
		require.Equal(t, http.StatusFound, r.Code)
		idpURL := r.Header.Get("Location")
		tracker := r.cookie("saml_")
		require.NotNil(t, tracker)
		samlResponse := driveIDPLogin(t, idpURL)

		acs := m.send(http.MethodPost, m.base+"/saml/acs", cookieHeader(tracker), url.Values{
			"SAMLResponse": {samlResponse}, "RelayState": {relayStateOf(t, idpURL)},
		})
		require.Equal(t, http.StatusFound, acs.Code, acs.Body)
		session := acs.cookie("saml_session")
		require.NotNil(t, session, "the ACS callback starts a session")
		assert.Contains(t, acs.Header.Get("Location"), config.OAuthPathPrefix+"/login?id=", "and returns to the login request")

		// Back at the login with a session: the hand-off completes.
		r = m.send(http.MethodGet, m.base+acs.Header.Get("Location"), cookieHeader(session), nil)
		require.Equal(t, http.StatusFound, r.Code, r.Body)
		r = m.send(http.MethodGet, r.Header.Get("Location"), nil, nil)
		require.Equal(t, http.StatusFound, r.Code, r.Body)
		require.True(t, strings.HasPrefix(r.Header.Get("Location"), oauthLoopback), r.Header.Get("Location"))
		cb, err := url.Parse(r.Header.Get("Location"))
		require.NoError(t, err)

		status, tok := m.exchange(cb.Query().Get("code"), verifier)
		require.Equal(t, http.StatusOK, status, "%v", tok)
		access := tok["access_token"].(string)

		claims := jwt.MapClaims{}
		_, _, err = jwt.NewParser().ParseUnverified(access, claims)
		require.NoError(t, err)
		assert.Equal(t, "carol@example.com", claims["sub"], "the NameID")
		assert.Equal(t, "carol@example.com", claims["email"])
		assert.Equal(t, []any{"os-mcp-readers"}, claims["groups"], "the SAML attribute, as the groups claim")

		r = m.send(http.MethodPost, m.base+mcpPath, bearer(access), nil)
		assert.Equal(t, http.StatusOK, r.Code, "and the group rule in the ACL lets the token in")

		// A client that does hold a valid SAML session cookie is still recognized.
		r = m.send(http.MethodPost, m.base+mcpPath, cookieHeader(session), nil)
		assert.Equal(t, http.StatusForbidden, r.Code, "authenticated, then refused by the ACL, which only names the token's source")
	})
}
