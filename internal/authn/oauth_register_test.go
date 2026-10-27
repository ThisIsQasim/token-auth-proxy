package authn

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const claudeCallback = "https://claude.ai/api/mcp/auth_callback"

func (m *oauthMW) register(body string) (*mwReply, map[string]any) {
	m.t.Helper()
	req, err := http.NewRequestWithContext(m.t.Context(), http.MethodPost, m.issuer()+"/register", strings.NewReader(body))
	require.NoError(m.t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.cli.Do(req)
	require.NoError(m.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(m.t, err)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return &mwReply{Code: resp.StatusCode, Header: resp.Header, Body: string(raw)}, out
}

// loginAsClient is loginAs for any client and redirect URI.
func (m *oauthMW) loginAsClient(clientID, redirect, challenge string) (code string, stopped *mwReply) {
	m.t.Helper()
	r := m.send(http.MethodGet, m.issuer()+"/authorize?"+url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid offline_access"}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode(), nil, nil)
	if r.Code != http.StatusFound || !strings.Contains(r.Header.Get("Location"), config.OAuthPathPrefix+"/login?id=") {
		return "", r
	}
	r = m.send(http.MethodGet, r.Header.Get("Location"), basicAuth("alice"), nil)
	require.Equal(m.t, http.StatusFound, r.Code, r.Body)
	r = m.send(http.MethodGet, r.Header.Get("Location"), nil, nil)
	require.Equal(m.t, http.StatusFound, r.Code, r.Body)
	require.True(m.t, strings.HasPrefix(r.Header.Get("Location"), redirect), r.Header.Get("Location"))
	loc, err := url.Parse(r.Header.Get("Location"))
	require.NoError(m.t, err)
	return loc.Query().Get("code"), nil
}

func (m *oauthMW) exchangeFor(clientID, redirect, code, verifier string) (int, map[string]any) {
	m.t.Helper()
	r := m.send(http.MethodPost, m.issuer()+"/token", nil, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier},
	})
	var out map[string]any
	require.NoError(m.t, json.Unmarshal([]byte(r.Body), &out))
	return r.Code, out
}

func newDynamicMW(t *testing.T, dynamic map[string]any) *oauthMW {
	t.Helper()
	m := newOAuthMW(t)
	m.dynamic = dynamic
	m.reload()
	return m
}

func TestOAuthMW_Register_EndToEnd(t *testing.T) {
	for name, redirect := range map[string]string{
		"a loopback client on any port": "http://localhost:51234/callback",
		"the hosted claude callback":    claudeCallback,
	} {
		t.Run(name, func(t *testing.T) {
			m := newDynamicMW(t, map[string]any{"enabled": true, "redirect_uris": []string{claudeCallback}})
			r, out := m.register(`{"client_name":"Claude Code","redirect_uris":["` + redirect + `"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`)
			require.Equal(t, http.StatusCreated, r.Code, r.Body)
			assert.Equal(t, "none", out["token_endpoint_auth_method"])
			assert.Equal(t, "no-store", r.Header.Get("Cache-Control"))
			clientID, _ := out["client_id"].(string)
			require.NotEmpty(t, clientID)

			verifier, challenge := pkcePair()
			code, stopped := m.loginAsClient(clientID, redirect, challenge)
			require.Nil(t, stopped)
			status, tok := m.exchangeFor(clientID, redirect, code, verifier)
			require.Equal(t, http.StatusOK, status, "%v", tok)

			access := tok["access_token"].(string)
			rr := m.send(http.MethodPost, m.base+mcpPath, bearer(access), nil)
			assert.Equal(t, http.StatusOK, rr.Code, "the token reaches the MCP endpoint")
			assert.Equal(t, backendBody, rr.Body)

			rr = m.send(http.MethodPost, m.issuer()+"/token", nil, url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {clientID},
			})
			assert.Equal(t, http.StatusOK, rr.Code, "and refreshes: %s", rr.Body)
		})
	}
}

func TestOAuthMW_Register_Rejections(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true})
	many := `"http://localhost/a"` + strings.Repeat(`,"http://localhost/a"`, 10)
	for name, c := range map[string]struct{ body, errCode string }{
		"a foreign https redirect":          {`{"redirect_uris":["https://evil.example/cb"]}`, "invalid_redirect_uri"},
		"http off loopback":                 {`{"redirect_uris":["http://example.com/cb"]}`, "invalid_redirect_uri"},
		"a loopback lookalike":              {`{"redirect_uris":["http://localhost.evil.example/cb"]}`, "invalid_redirect_uri"},
		"a fragment":                        {`{"redirect_uris":["http://localhost/cb#x"]}`, "invalid_redirect_uri"},
		"credentials in the URI":            {`{"redirect_uris":["http://user@localhost/cb"]}`, "invalid_redirect_uri"},
		"a javascript URI":                  {`{"redirect_uris":["javascript:alert(1)"]}`, "invalid_redirect_uri"},
		"no redirect URIs":                  {`{"client_name":"x"}`, "invalid_redirect_uri"},
		"too many redirect URIs":            {`{"redirect_uris":[` + many + `]}`, "invalid_redirect_uri"},
		"a confidential client":             {`{"redirect_uris":["http://localhost/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, "invalid_client_metadata"},
		"an unsupported grant":              {`{"redirect_uris":["http://localhost/cb"],"grant_types":["client_credentials"]}`, "invalid_client_metadata"},
		"an unsupported response type":      {`{"redirect_uris":["http://localhost/cb"],"response_types":["token"]}`, "invalid_client_metadata"},
		"a body that is not JSON":           {`redirect_uris=http://localhost/cb`, "invalid_client_metadata"},
		"a body past the size limit":        {`{"client_name":"` + strings.Repeat("a", 20<<10) + `","redirect_uris":["http://localhost/cb"]}`, "invalid_client_metadata"},
		"grants without authorization_code": {`{"redirect_uris":["http://localhost/cb"],"grant_types":["refresh_token"]}`, "invalid_client_metadata"},
		"redirect URIs of the wrong shape":  {`{"redirect_uris":"http://localhost/cb"}`, "invalid_client_metadata"},
	} {
		t.Run(name, func(t *testing.T) {
			r, out := m.register(c.body)
			assert.Equal(t, http.StatusBadRequest, r.Code, r.Body)
			assert.Equal(t, c.errCode, out["error"])
			assert.NotContains(t, r.Body, "client_id")
		})
	}
}

func TestOAuthMW_Register_ClientIDIsBoundToItsRedirects(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true})
	_, out := m.register(`{"redirect_uris":["http://localhost:9000/callback"]}`)
	clientID := out["client_id"].(string)
	_, challenge := pkcePair()

	for name, redirect := range map[string]string{
		"another loopback host":   "http://127.0.0.1:9000/callback",
		"another path":            "http://localhost:9000/elsewhere",
		"an https look-alike":     "https://localhost:9000/callback",
		"the hosted callback":     claudeCallback,
		"a foreign https address": "https://evil.example/cb",
	} {
		_, stopped := m.loginAsClient(clientID, redirect, challenge)
		require.NotNil(t, stopped, name)
		assert.NotEqual(t, http.StatusFound, stopped.Code, name)
	}

	for name, id := range map[string]string{
		"a tampered ID":  clientID[:len(clientID)-2] + "AA",
		"a made-up ID":   "not-a-client",
		"a truncated ID": clientID[:len(clientID)/2],
	} {
		_, stopped := m.loginAsClient(id, "http://localhost:9000/callback", challenge)
		require.NotNil(t, stopped, name)
		assert.NotEqual(t, http.StatusFound, stopped.Code, name)
	}
}

func TestOAuthMW_Register_FollowsTheLiveConfiguration(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true, "redirect_uris": []string{claudeCallback}})
	_, out := m.register(`{"redirect_uris":["` + claudeCallback + `"]}`)
	clientID := out["client_id"].(string)
	_, challenge := pkcePair()

	_, stopped := m.loginAsClient(clientID, claudeCallback, challenge)
	require.Nil(t, stopped)

	m.dynamic = map[string]any{"enabled": true, "redirect_uris": []string{}}
	m.reload()
	_, stopped = m.loginAsClient(clientID, claudeCallback, challenge)
	require.NotNil(t, stopped, "taking the callback off the allowlist ends the client")
	assert.NotEqual(t, http.StatusFound, stopped.Code)
	r, _ := m.register(`{"redirect_uris":["` + claudeCallback + `"]}`)
	assert.Equal(t, http.StatusBadRequest, r.Code, "and nobody can register it again")

	m.dynamic = nil
	m.reload()
	_, stopped = m.loginAsClient(clientID, "http://localhost:9000/callback", challenge)
	require.NotNil(t, stopped)
	r, _ = m.register(`{"redirect_uris":["http://localhost/cb"]}`)
	assert.Equal(t, http.StatusNotFound, r.Code, "switched off, registration does not exist")
}

func TestOAuthMW_Register_DiscoveryAdvertisesOnlyWhenOn(t *testing.T) {
	registration := func(m *oauthMW) any {
		r := m.send(http.MethodGet, m.issuer()+"/.well-known/openid-configuration", nil, nil)
		require.Equal(t, http.StatusOK, r.Code)
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.Body), &doc))
		return doc["registration_endpoint"]
	}
	m := newOAuthMW(t)
	assert.Nil(t, registration(m))
	r, _ := m.register(`{"redirect_uris":["http://localhost/cb"]}`)
	assert.Equal(t, http.StatusNotFound, r.Code)

	m.dynamic = map[string]any{"enabled": true}
	m.reload()
	assert.Equal(t, m.issuer()+"/register", registration(m))
}

func TestOAuthMW_Register_CORSAndMethods(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true})

	r := m.send(http.MethodOptions, m.issuer()+"/register", map[string]string{
		"Origin": "https://claude.ai", "Access-Control-Request-Method": "POST",
	}, nil)
	assert.Equal(t, http.StatusNoContent, r.Code)
	assert.Equal(t, "*", r.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, r.Header.Get("Access-Control-Allow-Methods"), "POST")

	reply, _ := m.register(`{"redirect_uris":["http://localhost/cb"]}`)
	assert.Equal(t, "*", reply.Header.Get("Access-Control-Allow-Origin"))

	r = m.send(http.MethodGet, m.issuer()+"/register", nil, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, r.Code)
	assert.Zero(t, m.backend.Hits(), "registration is never forwarded to the backend")
}

func TestOAuthMW_Register_ConfiguredClientsKeepWorking(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true})
	verifier, challenge := pkcePair()
	code, stopped := m.loginAs(basicAuth("alice"), challenge)
	require.Nil(t, stopped)
	status, tok := m.exchange(code, verifier)
	assert.Equal(t, http.StatusOK, status, "%v", tok)
}

func TestOAuthMW_Register_KeepsTheRedirectsStillPermitted(t *testing.T) {
	m := newDynamicMW(t, map[string]any{"enabled": true, "redirect_uris": []string{claudeCallback}})
	_, out := m.register(`{"redirect_uris":["http://localhost:9000/callback","` + claudeCallback + `"]}`)
	clientID := out["client_id"].(string)
	_, challenge := pkcePair()

	_, stopped := m.loginAsClient(clientID, claudeCallback, challenge)
	require.Nil(t, stopped)

	m.dynamic = map[string]any{"enabled": true}
	m.reload()
	_, stopped = m.loginAsClient(clientID, claudeCallback, challenge)
	require.NotNil(t, stopped, "the callback that left the list no longer works")
	assert.NotEqual(t, http.StatusFound, stopped.Code)
	_, stopped = m.loginAsClient(clientID, "http://localhost:9000/callback", challenge)
	assert.Nil(t, stopped, "but the client keeps the one that is still permitted")
}
