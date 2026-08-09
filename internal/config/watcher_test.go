package config

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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

	w, err := NewWatcher(path, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })
	require.Equal(t, "http://backend-a:9000", w.Current().Target)
}

func TestWatcher_ReloadOnAtomicRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, "target: http://backend-a:9000\n")

	w, err := NewWatcher(path, testLogger())
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

	w, err := NewWatcher(path, testLogger())
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

	w, err := NewWatcher(path, testLogger())
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

	w, err := NewWatcher(path, testLogger())
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
