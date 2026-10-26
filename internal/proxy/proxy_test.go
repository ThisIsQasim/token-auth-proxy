package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
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

// tlsBackend serves a certificate no public CA vouches for, and returns it as
// a PEM CA bundle: the self-signed leaf is its own trust anchor.
func tlsBackend(t *testing.T) (url, caPEM string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tls-backend-response"))
	}))
	t.Cleanup(srv.Close)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv.URL, string(pemBytes)
}

// otherCAPEM is a self-signed CA that has nothing to do with the backend's certificate.
// (httptest's TLS servers all share one built-in certificate, so another of them would not do.)
func otherCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// serveVia proxies one GET to the target of cfg with the transport BuildTransport makes for it.
func serveVia(t *testing.T, cfg *config.Config) *httptest.ResponseRecorder {
	t.Helper()
	cfg.ListenAddr = ":0"
	require.NoError(t, cfg.Validate())
	source := &fakeSource{tb: t}
	source.current.Store(cfg)

	rp := New(source, testLogger(), BuildTransport(cfg))
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	return rec
}

func TestBuildTransport_TargetCACert(t *testing.T) {
	url, caPEM := tlsBackend(t)

	t.Run("an https backend with a private CA is refused without it", func(t *testing.T) {
		rec := serveVia(t, &config.Config{Target: url})
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.NotContains(t, rec.Body.String(), "tls-backend-response")
	})

	t.Run("and proxied with it", func(t *testing.T) {
		rec := serveVia(t, &config.Config{Target: url, TargetCACert: caPEM})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "tls-backend-response", rec.Body.String())
	})

	t.Run("a different CA does not verify it, and the system roots are not added back", func(t *testing.T) {
		rec := serveVia(t, &config.Config{Target: url, TargetCACert: otherCAPEM(t)})
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})
}
