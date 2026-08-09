package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// fakeSource is a ConfigSource test double letting tests swap the target
// URL directly, without a real filesystem watcher.
type fakeSource struct {
	tb      testing.TB
	current atomic.Pointer[config.Config]
}

func newFakeSource(tb testing.TB, target string) *fakeSource {
	tb.Helper()
	s := &fakeSource{tb: tb}
	s.set(target)
	return s
}

func (s *fakeSource) Current() *config.Config { return s.current.Load() }

// set builds a fresh, validated Config pointing at target and publishes
// it — Validate() is what populates the unexported, parsed target URL
// TargetURL() returns, exactly as production code does via config.Load.
func (s *fakeSource) set(target string) {
	s.tb.Helper()
	cfg := &config.Config{ListenAddr: ":0", Target: target}
	require.NoError(s.tb, cfg.Validate())
	s.current.Store(cfg)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testTransport() http.RoundTripper {
	return http.DefaultTransport
}

func TestProxy_ForwardsToTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/hello", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-response"))
	}))
	defer backend.Close()

	source := newFakeSource(t, backend.URL)
	rp := New(source, testLogger(), testTransport())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/hello", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backend-response", rec.Body.String())
}

func TestProxy_AtomicSwapTakesEffectNextRequest(t *testing.T) {
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("A"))
	}))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("B"))
	}))
	defer backendB.Close()

	source := newFakeSource(t, backendA.URL)
	rp := New(source, testLogger(), testTransport())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	assert.Equal(t, "A", rec.Body.String())

	source.set(backendB.URL)

	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	rp.ServeHTTP(rec2, req2)
	assert.Equal(t, "B", rec2.Body.String())
}

func TestProxy_InFlightRequestNotDropped(t *testing.T) {
	release := make(chan struct{})
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte("A"))
	}))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("B"))
	}))
	defer backendB.Close()

	source := newFakeSource(t, backendA.URL)
	rp := New(source, testLogger(), testTransport())

	srv := httptest.NewServer(rp)
	defer srv.Close()

	type result struct {
		body string
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/", nil)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		resCh <- result{body: string(body)}
	}()

	// Give the request time to reach the (blocked) backend before swapping.
	time.Sleep(100 * time.Millisecond)
	source.set(backendB.URL)
	close(release)

	select {
	case res := <-resCh:
		require.NoError(t, res.err)
		assert.Equal(t, "A", res.body, "in-flight request must complete against the backend it started with")
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete")
	}
}

func TestProxy_BackendDown(t *testing.T) {
	// A closed listener's address: nothing is listening there.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := closed.URL
	closed.Close()

	source := newFakeSource(t, deadURL)
	rp := New(source, testLogger(), testTransport())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestHealthzHandler(t *testing.T) {
	h := HealthzHandler()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}
