//go:build integration

// Package integration exec's the real built binary and exercises it
// end-to-end: real listener, real filesystem, real config reloads —
// nothing mocked. Run via `make test-integration` or
// `go test -tags=integration ./test/integration/...`.
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

// assertBodyEventually polls url until it returns want or the timeout
// elapses, tolerating transient errors (e.g. a request landing mid-reload).
func assertBodyEventually(t *testing.T, url, want string, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	var last string
	var lastErr error
	for time.Now().Before(deadline) {
		body, err := testutil.FetchBody(ctx, url)
		if err == nil && body == want {
			return
		}
		last, lastErr = body, err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return %q; last body=%q last err=%v", url, want, last, lastErr)
}

func TestProxyHotReload(t *testing.T) {
	backendV1 := testutil.NewBackend(t, "v1")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendV1.URL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "v1", 2*time.Second)

	backendV2 := testutil.NewBackend(t, "v2")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendV2.URL))

	assertBodyEventually(t, baseURL+"/", "v2", 3*time.Second)
}

func TestProxyHotReload_MalformedConfigDoesNotDropTraffic(t *testing.T) {
	backendV1 := testutil.NewBackend(t, "v1")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendV1.URL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "v1", 2*time.Second)

	// An intermediate malformed write must not disrupt traffic.
	testutil.WriteAtomic(t, cfgPath, "target: [not valid yaml\n")
	time.Sleep(400 * time.Millisecond)
	body, err := testutil.FetchBody(context.Background(), baseURL+"/")
	require.NoError(t, err)
	assert.Equal(t, "v1", body, "malformed config write must not drop existing traffic")

	backendV2 := testutil.NewBackend(t, "v2")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendV2.URL))
	assertBodyEventually(t, baseURL+"/", "v2", 3*time.Second)
}

func TestProxyHealthz(t *testing.T) {
	backend := testutil.NewBackend(t, "v1")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backend.URL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	body, err := testutil.FetchBody(context.Background(), baseURL+"/healthz")
	require.NoError(t, err)
	assert.Equal(t, "ok", body)
}

func TestProxyStaticFlagMode(t *testing.T) {
	backend := testutil.NewBackend(t, "static-flag")

	proc := testutil.StartProxyArgs(t, "--target", backend.URL, "--listen-addr", ":0")
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "static-flag", 2*time.Second)
}

func TestProxyStaticEnvMode(t *testing.T) {
	backend := testutil.NewBackend(t, "static-env")

	proc := testutil.StartProxyWith(t, []string{"TAP_TARGET=" + backend.URL, "TAP_LISTEN_ADDR=:0"})
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "static-env", 2*time.Second)
}

// TestProxyFlagOverridePersistsAcrossFileReload is the full end-to-end
// (real binary, real subprocess, real file) proof of the precedence
// contract: a -target flag must keep winning over the config file even
// after the file changes the same field and triggers a real hot-reload.
func TestProxyFlagOverridePersistsAcrossFileReload(t *testing.T) {
	backendFile := testutil.NewBackend(t, "from-file")
	backendPinned := testutil.NewBackend(t, "pinned")

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendFile.URL))

	proc := testutil.StartProxyArgs(t, "--config", cfgPath, "--target", backendPinned.URL)
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "pinned", 2*time.Second)

	backendFileV2 := testutil.NewBackend(t, "from-file-v2")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backendFileV2.URL))

	// Give the watcher time to actually process the file change; the
	// override must still be in effect afterward, not just before it.
	time.Sleep(400 * time.Millisecond)
	body, err := testutil.FetchBody(context.Background(), baseURL+"/")
	require.NoError(t, err)
	assert.Equal(t, "pinned", body, "flag override must still win after a real file-triggered reload")
}

// TestProxyInboundAuthSchemaDoesNotBreakProxying is a light smoke test
// for the auth config schema: a config with both a JWT and a SAML
// source configured, but every one disabled: true, must still load and
// serve traffic normally, since the proxy stays "not enforcing" purely
// via the source-list-derived Enabled() — no separate key to flip, and
// nothing in this pass actually enforces auth yet regardless. This
// exercises the full real-binary path (flag parse -> Resolve/NewWatcher
// -> decode -> applyDefaults -> Validate -> serve) against the new
// schema, including the session_signing_key_env presence check.
func TestProxyInboundAuthSchemaDoesNotBreakProxying(t *testing.T) {
	backend := testutil.NewBackend(t, "v1")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, `
listen_addr: ":0"
target: `+backend.URL+`
inbound:
  auth:
    jwt:
      - name: jwt-a
        issuer: https://issuer.example.com
        jwks_url: https://issuer.example.com/jwks.json
        disabled: true
    saml:
      name: saml-a
      issuer: https://idp.example.com/metadata
      idp_metadata_url: https://idp.example.com/metadata
      sp_entity_id: https://proxy.example.com/saml/metadata
      acs_path: /saml/saml-a/acs
      session_cookie: saml_a_session
      session_signing_key_env: INTEGRATION_TEST_SAML_SESSION_KEY
      disabled: true
`)

	proc := testutil.StartProxyWith(t, []string{"INTEGRATION_TEST_SAML_SESSION_KEY=secret"}, "--config", cfgPath)
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "v1", 2*time.Second)
}

// TestProxyStaticEnvMode_JSONListAuthOverride proves the real binary's
// full Resolve -> static Config path populates Inbound.Auth.JWT from
// TAP_INBOUND_AUTH_JWT_JSON alone (no --config at all), and that
// traffic still proxies normally -- nothing is enforced yet, per the
// schema-only scope.
func TestProxyStaticEnvMode_JSONListAuthOverride(t *testing.T) {
	backend := testutil.NewBackend(t, "static-env-auth")

	jwtJSON := `[{"name":"jwt-a","issuer":"https://issuer.example.com","jwks_url":"https://issuer.example.com/jwks.json"}]`
	proc := testutil.StartProxyWith(t, []string{
		"TAP_TARGET=" + backend.URL,
		"TAP_LISTEN_ADDR=:0",
		"TAP_INBOUND_AUTH_JWT_JSON=" + jwtJSON,
	})
	baseURL := "http://" + proc.Addr

	assertBodyEventually(t, baseURL+"/", "static-env-auth", 2*time.Second)
}

func TestProxyGracefulShutdown(t *testing.T) {
	backend := testutil.NewBackend(t, "v1")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, testutil.ConfigYAML(":0", backend.URL))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr
	assertBodyEventually(t, baseURL+"/", "v1", 2*time.Second)

	require.NoError(t, proc.Cmd.Process.Signal(os.Interrupt))

	done := make(chan error, 1)
	go func() { done <- proc.Cmd.Wait() }()
	select {
	case err := <-done:
		assert.NoError(t, err, "process should exit cleanly on SIGINT")
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not shut down within timeout")
	}
}
