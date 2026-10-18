//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

const oidcLoginSecretEnv = "OIDC_LOGIN_INTEGRATION_SECRET"

// oidcLoginConfigYAML builds a config with one JWT source that has
// browser login. secret=true makes it a confidential client; basic adds
// a Basic source, which makes the login picker appear.
func oidcLoginConfigYAML(backendURL, spBaseURL string, idp *testutil.TestIDP, secret, basic bool) string {
	cfg := fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        oidc_discovery_url: %q
        login:
          client_id: proxy-client
          sp_base_url: %q
`, backendURL, idp.Issuer, idp.DiscoveryURL, spBaseURL)
	if secret {
		cfg += "          client_secret: \"${env:" + oidcLoginSecretEnv + "}\"\n"
	}
	if basic {
		hash, err := basicHash()
		if err != nil {
			panic(err)
		}
		cfg += fmt.Sprintf(`    basic:
      realm: test-realm
      users:
        - username: alice
          password_hash: %q
`, hash)
	}
	return cfg
}

func startOIDCLoginProxy(t *testing.T, idp *testutil.TestIDP, secret, basic bool) string {
	t.Helper()
	backend := testutil.NewBackend(t, "backend-ok")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")

	testutil.WriteAtomic(t, cfgPath, oidcLoginConfigYAML(backend.URL, "http://127.0.0.1:0", idp, secret, basic))
	proc := testutil.StartProxyWith(t, []string{oidcLoginSecretEnv + "=integration-secret"}, "--config", cfgPath)
	base := "http://" + proc.Addr
	testutil.WriteAtomic(t, cfgPath, oidcLoginConfigYAML(backend.URL, base, idp, secret, basic))
	time.Sleep(200 * time.Millisecond) // the watcher's reload is async, see StartProxySAML
	return base
}

// page is a response whose body has already been read and closed.
type page struct {
	StatusCode int
	Path       string
}

func browserGet(t *testing.T, c *http.Client, url string) (*page, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return &page{StatusCode: resp.StatusCode, Path: resp.Request.URL.Path}, string(body)
}

func TestProxyOIDCLogin_ConfidentialClient(t *testing.T) {
	idp := testutil.NewTestIDP(t)
	idp.RegisterClient("proxy-client", "integration-secret")
	base := startOIDCLoginProxy(t, idp, true, false)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	resp, body := browserGet(t, c, base+"/protected")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend-ok", body)
	tr := idp.LastTokenRequest()
	assert.Equal(t, "basic", tr.AuthMethod)
	assert.True(t, tr.SecretOK)
	assert.True(t, tr.VerifierOK)

	// The cookie carries later requests without another login.
	resp, body = browserGet(t, c, base+"/protected")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyOIDCLogin_PublicClient(t *testing.T) {
	idp := testutil.NewTestIDP(t)
	idp.RegisterClient("proxy-client", "")
	base := startOIDCLoginProxy(t, idp, false, false)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	resp, body := browserGet(t, c, base+"/")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend-ok", body)
	tr := idp.LastTokenRequest()
	assert.Equal(t, "none", tr.AuthMethod)
	assert.True(t, tr.VerifierOK)
}

func TestProxyOIDCLogin_PickerWithBasic(t *testing.T) {
	idp := testutil.NewTestIDP(t)
	idp.RegisterClient("proxy-client", "")
	base := startOIDCLoginProxy(t, idp, false, true)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	// Two methods: the browser lands on the picker.
	resp, body := browserGet(t, c, base+"/page")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/_tap/login", resp.Path)
	assert.Contains(t, body, "Sign in with username and password")

	// Choosing OIDC completes the login and returns to the page.
	resp, body = browserGet(t, c, base+"/_tap/login/jwt?source=idp&return_to=%2Fpage")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "backend-ok", body)
}
