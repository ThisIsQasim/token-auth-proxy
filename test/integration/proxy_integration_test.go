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
