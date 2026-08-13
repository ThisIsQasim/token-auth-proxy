//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

const samlSessionKeyValue = "01234567890123456789012345678901" // 32 bytes, satisfies minSessionSigningKeyLen
const samlSessionKeyEnv = "SAML_INTEGRATION_TEST_SESSION_KEY"

var samlIntegrationEnv = []string{samlSessionKeyEnv + "=" + samlSessionKeyValue}

// getNoRedirect performs one GET against url with the given cookies,
// never following a redirect — unlike testutil.FetchWith (and anything
// built on it, e.g. assertStatusEventually), which uses Go's default
// http.Client and so transparently follows a 302 all the way to the
// idp's own 200 response, making a redirect impossible to observe
// through it. Callers must close the returned response's Body.
func getNoRedirect(t *testing.T, url string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	client := testutil.NewCookieClient(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// assertSAMLRedirectEventually polls url (via getNoRedirect, so a
// redirect is actually observable — see its doc comment) until it
// returns a 302, or the timeout elapses.
func assertSAMLRedirectEventually(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastStatus int
	for time.Now().Before(deadline) {
		resp := getNoRedirect(t, url)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			return
		}
		lastStatus = resp.StatusCode
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to redirect (302); last status=%d", url, lastStatus)
}

// samlConfigYAML builds a full config YAML for a SAML-only proxy
// trusting idp, with acsPath/sessionCookie/sessionDuration parameterized
// so hot-reload tests can flip them without duplicating the whole
// template. sessionDuration defaults to "1h" when empty. sp_entity_id
// is always spBaseURL+"/saml/metadata", matching
// testutil.StartProxySAML's fixed convention.
func samlConfigYAML(backendURL, spBaseURL string, idp *testutil.TestSAMLIDP, acsPath, sessionCookie, sessionDuration string) string {
	if sessionDuration == "" {
		sessionDuration = "1h"
	}
	return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    saml:
      name: saml-a
      issuer: %q
      idp_metadata_url: %q
      sp_base_url: %q
      sp_entity_id: %q
      acs_path: %q
      session_cookie: %q
      session_signing_key_env: %s
      session_duration: %q
`, backendURL, idp.Issuer, idp.MetadataURL, spBaseURL, spBaseURL+"/saml/metadata", acsPath, sessionCookie, samlSessionKeyEnv, sessionDuration)
}

func TestProxySAML_UnauthenticatedRedirectsToIdP(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(spBaseURL string) string {
			return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	client := testutil.NewCookieClient(t)
	resp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "SAMLRequest=")
}

func TestProxySAML_LoginCompletesAndSessionProxies(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", map[string][]string{"email": {"user@example.com"}})

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(spBaseURL string) string {
			return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	client := testutil.NewCookieClient(t)
	acsResp := testutil.CompleteSAMLLogin(t, client, baseURL+"/protected")
	defer func() { _ = acsResp.Body.Close() }()
	require.Equal(t, http.StatusFound, acsResp.StatusCode)
	assert.Equal(t, "/protected", acsResp.Header.Get("Location"))

	var sawSessionCookie bool
	for _, c := range acsResp.Cookies() {
		if c.Name == "saml_session" {
			sawSessionCookie = true
		}
	}
	assert.True(t, sawSessionCookie, "expected the session cookie to be set after a completed login")

	// client's jar now carries the session cookie automatically.
	protectedResp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
	require.NoError(t, err)
	defer func() { _ = protectedResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, protectedResp.StatusCode, "a valid session must now proxy through")
}

// TestProxySAML_EncryptedAssertion_LoginSucceeds proves sp_key_env/
// sp_cert work end to end through the real compiled binary: with a
// real SP keypair configured and that same certificate registered with
// the fixture IdP as an encryption key, the IdP encrypts the assertion
// for real (see TestSAMLFullRoundTrip_EncryptedAssertion_DecryptsAndAuthenticates
// in internal/authn for the unit-level proof that inspects the raw
// wire response) and the real proxy process must decrypt it
// transparently for the login to succeed at all.
func TestProxySAML_EncryptedAssertion_LoginSucceeds(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cert, spKeyPEM, spCertPEM := testutil.GenerateSPKeyCertPEM(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	var spBaseURL string
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(base string) string {
			spBaseURL = base
			return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    saml:
      name: saml-a
      issuer: %q
      idp_metadata_url: %q
      sp_base_url: %q
      sp_entity_id: %q
      acs_path: "/saml/acs"
      session_cookie: "saml_session"
      session_signing_key_env: %s
      sp_key_env: SAML_INTEGRATION_TEST_SP_KEY
      sp_cert: %q
`, backend.URL, idp.Issuer, idp.MetadataURL, base, base+"/saml/metadata", samlSessionKeyEnv, spCertPEM)
		},
		append([]string{"SAML_INTEGRATION_TEST_SP_KEY=" + spKeyPEM}, samlIntegrationEnv...),
	)
	baseURL := "http://" + proc.Addr

	// StartProxySAML already called idp.RegisterSP for spBaseURL (the
	// real, resolved address) — add the encryption cert to that same
	// registered SP now that it exists.
	idp.RegisterSPEncryptionCert(spBaseURL+"/saml/metadata", cert)

	client := testutil.NewCookieClient(t)
	acsResp := testutil.CompleteSAMLLogin(t, client, baseURL+"/protected")
	defer func() { _ = acsResp.Body.Close() }()
	require.Equal(t, http.StatusFound, acsResp.StatusCode, "the proxy must have successfully decrypted the assertion to complete the login")
	assert.Equal(t, "/protected", acsResp.Header.Get("Location"))

	protectedResp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
	require.NoError(t, err)
	defer func() { _ = protectedResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, protectedResp.StatusCode, "the decrypted assertion's session must authenticate normally")
}

func TestProxySAML_TamperedOrExpiredSession_RedirectsNotRejects(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")

	t.Run("tampered", func(t *testing.T) {
		idp := testutil.NewTestSAMLIDP(t)
		idp.SetUser("user@example.com", nil)
		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
			func(spBaseURL string) string {
				return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "")
			},
			samlIntegrationEnv,
		)
		baseURL := "http://" + proc.Addr

		resp := getNoRedirect(t, baseURL+"/protected", &http.Cookie{Name: "saml_session", Value: "not-a-valid-session-token"})
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusFound, resp.StatusCode, "a tampered session must redirect to the idp, not 401 or 200")
	})

	t.Run("expired", func(t *testing.T) {
		idp := testutil.NewTestSAMLIDP(t)
		idp.SetUser("user@example.com", nil)
		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
			func(spBaseURL string) string {
				return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "1s")
			},
			samlIntegrationEnv,
		)
		baseURL := "http://" + proc.Addr

		client := testutil.NewCookieClient(t)
		acsResp := testutil.CompleteSAMLLogin(t, client, baseURL+"/protected")
		_ = acsResp.Body.Close()
		require.Equal(t, http.StatusFound, acsResp.StatusCode)

		time.Sleep(2 * time.Second) // outlive the 1s session_duration

		protectedResp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
		require.NoError(t, err)
		defer func() { _ = protectedResp.Body.Close() }()
		assert.Equal(t, http.StatusFound, protectedResp.StatusCode, "an expired session must redirect to the idp, not 401 or 200")
	})
}

// TestProxySAML_HotReload_ChangesSessionCookieAndACSPath is the
// headline reload test, mirroring
// TestProxyJWT_HotReloadChangesTrustedIssuers's role for the JWT leg: a
// session established under one session_cookie/acs_path stops being
// recognized the moment those fields change via a real hot-reload, with
// no process restart.
func TestProxySAML_HotReload_ChangesSessionCookieAndACSPath(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	var spBaseURL string
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(base string) string {
			spBaseURL = base
			return samlConfigYAML(backend.URL, base, idp, "/saml/acs", "saml_session_v1", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	client := testutil.NewCookieClient(t)
	acsResp := testutil.CompleteSAMLLogin(t, client, baseURL+"/protected")
	_ = acsResp.Body.Close()
	require.Equal(t, http.StatusFound, acsResp.StatusCode)

	protectedResp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
	require.NoError(t, err)
	_ = protectedResp.Body.Close()
	require.Equal(t, http.StatusOK, protectedResp.StatusCode, "session must work under the original cookie name")

	// Hot-reload: new cookie name and new acs path, same idp/entity id —
	// re-register the SP under the new acs path first, matching what a
	// real operator's coordinated IdP-side + proxy-side change looks like.
	idp.RegisterSP(spBaseURL+"/saml/metadata", spBaseURL+"/saml/acs-v2")
	testutil.WriteAtomic(t, cfgPath, samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs-v2", "saml_session_v2", ""))

	// An unauthenticated request would redirect under either the old or
	// new config, so it can't prove the reload actually took effect —
	// poll with client's still-present old-named session cookie
	// instead: it only starts redirecting once the source genuinely
	// stops recognizing "saml_session_v1" as its session cookie name.
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := client.Get(baseURL + "/protected") //nolint:noctx // test-only
		require.NoError(t, err)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the old session_cookie name to stop being recognized after reload (last status=%d)", resp.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A fresh login under the new config must now work end to end.
	acsResp2 := testutil.CompleteSAMLLogin(t, client, baseURL+"/protected")
	defer func() { _ = acsResp2.Body.Close() }()
	require.Equal(t, http.StatusFound, acsResp2.StatusCode)
	var sawNewCookie bool
	for _, c := range acsResp2.Cookies() {
		if c.Name == "saml_session_v2" {
			sawNewCookie = true
		}
	}
	assert.True(t, sawNewCookie, "expected the reloaded session_cookie name to be used")
}

func TestProxySAML_JWTAndSAMLCoexist(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	jwtIDP := testutil.NewTestIDP(t)
	samlIDP := testutil.NewTestSAMLIDP(t)
	samlIDP.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	proc := testutil.StartProxySAML(t, cfgPath, samlIDP, "/saml/acs",
		func(spBaseURL string) string {
			return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s    saml:
      name: saml-a
      issuer: %q
      idp_metadata_url: %q
      sp_base_url: %q
      sp_entity_id: %q
      acs_path: /saml/acs
      session_cookie: saml_session
      session_signing_key_env: %s
`, backend.URL, jwtSourceYAML(jwtIDP), samlIDP.Issuer, samlIDP.MetadataURL, spBaseURL, spBaseURL+"/saml/metadata", samlSessionKeyEnv)
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	t.Run("valid jwt forwards without consulting saml", func(t *testing.T) {
		token := jwtIDP.Sign(t, jwt.RegisteredClaims{Issuer: jwtIDP.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
		status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "backend-ok", body)
	})

	t.Run("no credential falls through to saml redirect", func(t *testing.T) {
		resp := getNoRedirect(t, baseURL+"/")
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})
}

func TestProxySAML_ACSPathNeverPanics_HealthzStaysUp(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(spBaseURL string) string {
			return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	// A bare, malformed GET straight to the acs path — must not crash
	// the server (a handler panic only kills the one connection; the
	// real proof nothing crashed is that /healthz still responds after).
	status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/saml/acs", nil)
	require.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, status)

	body, err := testutil.FetchBody(context.Background(), baseURL+"/healthz")
	require.NoError(t, err)
	assert.Equal(t, "ok", body)
}

func TestProxySAML_HealthzStaysUnauthenticated(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(spBaseURL string) string {
			return samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	body, err := testutil.FetchBody(context.Background(), baseURL+"/healthz")
	require.NoError(t, err)
	assert.Equal(t, "ok", body)
}

func TestProxySAML_HotReload_DisablingStopsEnforcing(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	var spBaseURL string
	proc := testutil.StartProxySAML(t, cfgPath, idp, "/saml/acs",
		func(base string) string {
			spBaseURL = base
			return samlConfigYAML(backend.URL, base, idp, "/saml/acs", "saml_session", "")
		},
		samlIntegrationEnv,
	)
	baseURL := "http://" + proc.Addr

	assertSAMLRedirectEventually(t, baseURL+"/", 2*time.Second)

	disabled := samlConfigYAML(backend.URL, spBaseURL, idp, "/saml/acs", "saml_session", "") + "      disabled: true\n"
	testutil.WriteAtomic(t, cfgPath, disabled)

	assertStatusEventually(t, baseURL+"/", http.StatusOK, 3*time.Second)
}
