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

// assertStatusEventually polls url until it returns wantStatus or the
// timeout elapses, tolerating transient connection errors — used the
// same way assertBodyEventually is, but for cases (like a reload
// flipping enforcement on/off) where the interesting signal is the
// status code, not the body.
func assertStatusEventually(t *testing.T, url string, wantStatus int, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		status, _, _, err := testutil.FetchWith(ctx, url, nil)
		if err == nil && status == wantStatus {
			return
		}
		lastStatus, lastErr = status, err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return status %d; last status=%d last err=%v", url, wantStatus, lastStatus, lastErr)
}

func bearerHeader(token string) http.Header {
	return http.Header{"Authorization": []string{"Bearer " + token}}
}

func jwtSourceYAML(idp *testutil.TestIDP) string {
	return fmt.Sprintf(`      - name: idp
        issuer: %q
        jwks_url: %q
`, idp.Issuer, idp.JWKSURL)
}

func TestProxyJWT_ValidTokenIsProxied(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyJWT_MissingTokenIsRejected(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, header, _, err := testutil.FetchWith(context.Background(), baseURL+"/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "Bearer", header.Get("WWW-Authenticate"))
}

func TestProxyJWT_InvalidTokenIsRejected(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	t.Run("wrong signing key", func(t *testing.T) {
		other := testutil.NewTestIDP(t, testutil.WithIssuer(idp.Issuer))
		other.Rotate(t) // force distinct key material from idp's
		token := other.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("expired", func(t *testing.T) {
		token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour))})
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("unknown issuer", func(t *testing.T) {
		other := testutil.NewTestIDP(t, testutil.WithIssuer("https://unconfigured-issuer.example.com"))
		token := other.Sign(t, jwt.RegisteredClaims{Issuer: other.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}

func TestProxyJWT_AudienceMismatch(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        jwks_url: %q
        audiences: ["tap"]
`, backend.URL, idp.Issuer, idp.JWKSURL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	t.Run("wrong audience rejected", func(t *testing.T) {
		token := idp.Sign(t, jwt.RegisteredClaims{
			Issuer: idp.Issuer, Audience: jwt.ClaimStrings{"other"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("matching audience accepted", func(t *testing.T) {
		token := idp.Sign(t, jwt.RegisteredClaims{
			Issuer: idp.Issuer, Audience: jwt.ClaimStrings{"tap"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})
}

func TestProxyJWT_HealthzStaysUnauthenticated(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	body, err := testutil.FetchBody(context.Background(), baseURL+"/healthz")
	require.NoError(t, err)
	assert.Equal(t, "ok", body)
}

func TestProxyJWT_OIDCDiscovery(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        oidc_discovery_url: %q
`, backend.URL, idp.Issuer, idp.DiscoveryURL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyJWT_CookieCredentialLocation(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        jwks_url: %q
        credentials:
          - location: cookie
            name: session
`, backend.URL, idp.Issuer, idp.JWKSURL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", http.Header{"Cookie": []string{"session=" + token}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

// TestProxyJWT_HotReloadChangesTrustedIssuers is the headline reload
// test: config keeps hot-reloading which issuer is trusted, with no
// process restart, and the real Registry correctly evicts/rebuilds
// resolvers along the way.
func TestProxyJWT_HotReloadChangesTrustedIssuers(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idpA := testutil.NewTestIDP(t, testutil.WithIssuer("https://a.example.com"))
	idpB := testutil.NewTestIDP(t, testutil.WithIssuer("https://b.example.com"))
	idpB.Rotate(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	configTrusting := func(idp *testutil.TestIDP) string {
		return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp))
	}
	testutil.WriteAtomic(t, cfgPath, configTrusting(idpA))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	tokenA := idpA.Sign(t, jwt.RegisteredClaims{Issuer: idpA.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	tokenB := idpB.Sign(t, jwt.RegisteredClaims{Issuer: idpB.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(tokenA))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "token A must work while A is trusted")

	testutil.WriteAtomic(t, cfgPath, configTrusting(idpB))

	deadline := time.Now().Add(3 * time.Second)
	for {
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(tokenA))
		if err == nil && status == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for token A to stop working after reload (last status=%d err=%v)", status, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	status, _, _, err = testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(tokenB))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status, "token B must work once B is trusted")

	// Reload back to A and confirm it recovers — eviction isn't one-way.
	testutil.WriteAtomic(t, cfgPath, configTrusting(idpA))
	deadline = time.Now().Add(3 * time.Second)
	for {
		status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(tokenA))
		if err == nil && status == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for token A to work again after reloading back (last status=%d err=%v)", status, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestProxyJWT_HotReloadEnablesAndDisablesEnforcement proves enforcement
// itself (not just which issuer is trusted) can be toggled live.
func TestProxyJWT_HotReloadEnablesAndDisablesEnforcement(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backend.URL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "backend-ok", 2*time.Second)

	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))
	assertStatusEventually(t, baseURL+"/", http.StatusUnauthorized, 3*time.Second)

	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        jwks_url: %q
        disabled: true
`, backend.URL, idp.Issuer, idp.JWKSURL))
	assertStatusEventually(t, baseURL+"/", http.StatusOK, 3*time.Second)
}

func TestProxyJWT_MalformedConfigDuringEnforcementDoesNotDropEnforcement(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	testutil.WriteAtomic(t, cfgPath, "target: [not valid yaml\n")
	time.Sleep(400 * time.Millisecond)

	statusValid, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusValid, "a valid token must still work after a malformed reload")

	statusMissing, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusMissing, "a missing token must still be rejected after a malformed reload")
}

// TestProxyJWT_EnabledViaEnvJSONOverride is a regression test for a
// coverage gap found in review: TestProxyStaticEnvMode_JSONListAuthOverride
// (proxy_integration_test.go) proves the TAP_INBOUND_AUTH_JWT_JSON
// plumbing loads correctly, but deliberately uses a disabled source, so
// no test anywhere actually exercised "a JWT source loaded purely via
// the env-JSON override (no --config file at all) really enforces" —
// every enforcement test above uses --config instead. A future change
// that broke wiring specifically for env-JSON-sourced entries (e.g.
// silently forcing Disabled regardless of the JSON payload) would have
// gone undetected.
func TestProxyJWT_EnabledViaEnvJSONOverride(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	jwtJSON := fmt.Sprintf(`[{"name":"idp","issuer":%q,"jwks_url":%q}]`, idp.Issuer, idp.JWKSURL)
	proc := testutil.StartProxyWith(t, []string{
		"TAP_TARGET=" + backend.URL,
		"TAP_LISTEN_ADDR=:0",
		"TAP_INBOUND_AUTH_JWT_JSON=" + jwtJSON,
	})
	baseURL := "http://" + proc.Addr

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", bearerHeader(token))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)

	statusMissing, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusMissing, "an env-JSON-sourced enabled jwt source must actually enforce")
}
