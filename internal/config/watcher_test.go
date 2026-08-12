package config

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// syncBuffer wraps bytes.Buffer with a mutex: the watcher's reload
// logging happens on its own goroutine (see Start), so a test reading
// the buffer's contents from the main goroutine needs to synchronize
// with that, not just bytes.Buffer's own (non-concurrency-safe) methods.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// bufferLogger is like testLogger but writes to buf so a test can assert
// on the actual log output rather than just the resulting Config.
func bufferLogger(buf *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func writeAtomic(t *testing.T, path, contents string) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(contents), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

func startWatcher(t *testing.T, w *Watcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("watcher did not stop after context cancellation")
		}
	})
}

// waitForTimeout is used by every waitFor call in this file; kept as a
// named const rather than a parameter since no test currently needs a
// different value.
const waitForTimeout = 2 * time.Second

// waitFor polls fn until it returns true or waitForTimeout elapses.
func waitFor(t *testing.T, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(waitForTimeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

func TestWatcher_InitialLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, nil, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	require.Equal(t, "http://backend-a:9000", w.Current().Target)
}

func TestWatcher_ReloadOnAtomicRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, nil, testLogger())
	require.NoError(t, err)
	startWatcher(t, w)

	writeAtomic(t, path, "target: http://backend-b:9000\n")

	ok := waitFor(t, func() bool {
		return w.Current().Target == "http://backend-b:9000"
	})
	assert.True(t, ok, "expected reload to pick up new target, got %q", w.Current().Target)
}

func TestWatcher_DebounceCoalesces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, nil, testLogger())
	require.NoError(t, err)
	w.debounce = 100 * time.Millisecond
	startWatcher(t, w)

	for i := 0; i < 5; i++ {
		writeAtomic(t, path, "target: http://backend-final:9000\n")
		time.Sleep(10 * time.Millisecond)
	}

	ok := waitFor(t, func() bool {
		return w.Current().Target == "http://backend-final:9000"
	})
	require.True(t, ok)

	// Give any straggler reloads a moment to land, then assert the burst
	// coalesced into a small number of reloads, not one per write.
	time.Sleep(300 * time.Millisecond)
	assert.LessOrEqual(t, w.ReloadCount(), int64(2), "expected debounce to coalesce rapid writes")
}

func TestWatcher_MalformedYAMLKeepsOldConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, nil, testLogger())
	require.NoError(t, err)
	startWatcher(t, w)

	require.Equal(t, "http://backend-a:9000", w.Current().Target)

	writeAtomic(t, path, "target: [not valid yaml\n")
	// Give it time to attempt (and fail) a reload.
	time.Sleep(400 * time.Millisecond)
	assert.Equal(t, "http://backend-a:9000", w.Current().Target, "malformed config must not replace the running config")

	writeAtomic(t, path, "target: http://backend-b:9000\n")
	ok := waitFor(t, func() bool {
		return w.Current().Target == "http://backend-b:9000"
	})
	assert.True(t, ok, "expected recovery once a valid config lands")
}

func TestWatcher_SurvivesRemoveThenRecreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, nil, testLogger())
	require.NoError(t, err)
	startWatcher(t, w)

	require.NoError(t, os.Remove(path))
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, "http://backend-a:9000", w.Current().Target, "old config should hold during the gap")

	writeAtomic(t, path, "target: http://backend-b:9000\n")
	ok := waitFor(t, func() bool {
		return w.Current().Target == "http://backend-b:9000"
	})
	assert.True(t, ok, "expected reload once the file reappears")
}

// TestWatcher_FlagOverridePersistsAcrossReload is the concrete proof of
// the precedence contract (flag > env > file > default) applying on
// every reload, not just the initial load: a flag-overridden field must
// keep winning even after the file changes the same field underneath
// it, while a field with no override must keep hot-reloading normally.
func TestWatcher_FlagOverridePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "listen_addr: \":8080\"\ntarget: http://from-file:9000\n")

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	require.NoError(t, fs.Parse([]string{"--listen-addr", ":9999"}))

	w, err := NewWatcher(path, fs, testLogger())
	require.NoError(t, err)
	startWatcher(t, w)

	require.Equal(t, ":9999", w.Current().ListenAddr, "flag override should win over the file at startup")
	require.Equal(t, "http://from-file:9000", w.Current().Target, "non-overridden fields still come from the file")

	// Change both fields in the file.
	writeAtomic(t, path, "listen_addr: \":7000\"\ntarget: http://from-file-v2:9000\n")

	ok := waitFor(t, func() bool {
		return w.Current().Target == "http://from-file-v2:9000"
	})
	require.True(t, ok, "expected target (not overridden) to hot-reload from the file")

	assert.Equal(t, ":9999", w.Current().ListenAddr,
		"flag override on listen_addr must still win after the reload, even though the file changed it")
}

// TestWatcher_AuthHotReloads is a regression test for the
// reflect.DeepEqual fix in reload(): without it, adding an inbound.auth
// block wouldn't log "config reloaded" at all, since Target doesn't
// change. It also proves Disabled is honored live, and that
// InboundAuthConfig.Enabled() flows through a hot-reload's result.
func TestWatcher_AuthHotReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	buf := &syncBuffer{}
	w, err := NewWatcher(path, nil, bufferLogger(buf))
	require.NoError(t, err)
	startWatcher(t, w)

	require.False(t, w.Current().Inbound.Auth.Enabled(), "no auth configured yet")

	writeAtomic(t, path, `
target: http://backend-a:9000
inbound:
  auth:
    jwt:
      - name: jwt-a
        issuer: https://issuer.example.com
        jwks_url: https://issuer.example.com/jwks.json
`)

	ok := waitFor(t, func() bool {
		return w.Current().Inbound.Auth.Enabled() && len(w.Current().Inbound.Auth.JWT) == 1
	})
	require.True(t, ok, "expected the new jwt source to hot-reload in")

	logs := buf.String()
	assert.Contains(t, logs, "config reloaded", "an inbound.auth-only change must still trigger the reload log")
	assert.NotContains(t, logs, "restart the process", "inbound.auth is hot-reloaded, not restart-required")

	_, found := w.Current().Inbound.Auth.JWTSourceByIssuer("https://issuer.example.com")
	assert.True(t, found)

	// Disable the only source; Enabled() must flip back to false, and
	// the lookup must stop finding it.
	writeAtomic(t, path, `
target: http://backend-a:9000
inbound:
  auth:
    jwt:
      - name: jwt-a
        issuer: https://issuer.example.com
        jwks_url: https://issuer.example.com/jwks.json
        disabled: true
`)

	ok = waitFor(t, func() bool {
		return !w.Current().Inbound.Auth.Enabled()
	})
	assert.True(t, ok, "expected Enabled() to flip to false once the only source is disabled")

	_, found = w.Current().Inbound.Auth.JWTSourceByIssuer("https://issuer.example.com")
	assert.False(t, found, "a disabled source must not be found by lookup after a hot-reload")
}

// TestWatcher_JSONListOverridePersistsAcrossReload mirrors
// TestWatcher_FlagOverridePersistsAcrossReload for the JSON-blob
// override: TAP_INBOUND_AUTH_JWT_JSON must keep winning over the file's
// own inbound.auth.jwt across a real reload, not just at startup.
func TestWatcher_JSONListOverridePersistsAcrossReload(t *testing.T) {
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `[{"name":"from-env","issuer":"https://env.example.com","jwks_url":"https://env.example.com/jwks.json"}]`)

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, `
target: http://backend-a:9000
inbound:
  auth:
    jwt:
      - name: from-file
        issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	require.NoError(t, fs.Parse(nil))

	w, err := NewWatcher(path, fs, testLogger())
	require.NoError(t, err)
	startWatcher(t, w)

	require.Len(t, w.Current().Inbound.Auth.JWT, 1)
	require.Equal(t, "from-env", w.Current().Inbound.Auth.JWT[0].Name, "env override should win over the file at startup")

	// Change the file's list; the env override must still win after a
	// real reload, not just at the initial load.
	writeAtomic(t, path, `
target: http://backend-a:9000
inbound:
  auth:
    jwt:
      - name: from-file-v2
        issuer: https://file-v2.example.com
        jwks_url: https://file-v2.example.com/jwks.json
`)

	ok := waitFor(t, func() bool {
		return w.ReloadCount() > 0
	})
	require.True(t, ok, "expected a reload to happen")

	require.Len(t, w.Current().Inbound.Auth.JWT, 1)
	assert.Equal(t, "from-env", w.Current().Inbound.Auth.JWT[0].Name,
		"env override on inbound.auth.jwt must still win after the reload, even though the file changed it")
}
