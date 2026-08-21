package authn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeKeyfuncCall records one call made to a fakeNewKeyfunc.
type fakeKeyfuncCall struct {
	ctx     context.Context
	jwksURL string
	refresh time.Duration
	client  *http.Client
}

// fakeKeyfuncStub is a minimal keyfunc.Keyfunc stand-in — it never
// touches the network, so jwks_test.go can assert on Registry's
// build/evict bookkeeping deterministically without any real JWKS
// server. Only KeyfuncCtx is ever exercised by Registry itself; the
// other three methods exist solely to satisfy the interface.
type fakeKeyfuncStub struct{}

func (fakeKeyfuncStub) Keyfunc(_ *jwt.Token) (any, error) { return nil, nil }
func (fakeKeyfuncStub) KeyfuncCtx(_ context.Context) jwt.Keyfunc {
	return func(_ *jwt.Token) (any, error) { return nil, nil }
}
func (fakeKeyfuncStub) Storage() jwkset.Storage { return nil }
func (fakeKeyfuncStub) VerificationKeySet(_ context.Context) (jwt.VerificationKeySet, error) {
	return jwt.VerificationKeySet{}, nil
}

// newFakeNewKeyfunc returns a newKeyfuncFunc that records every call
// (including the context it was handed, so a test can assert on
// ctx.Done() to prove eviction cancels it, and the client, so a test
// can assert which one the registry picked for the source) and either
// succeeds or fails according to shouldFail.
func newFakeNewKeyfunc(calls *[]fakeKeyfuncCall, mu *sync.Mutex, shouldFail func(jwksURL string) error) newKeyfuncFunc {
	return func(ctx context.Context, jwksURL string, refresh time.Duration, client *http.Client) (keyfunc.Keyfunc, error) {
		mu.Lock()
		*calls = append(*calls, fakeKeyfuncCall{ctx: ctx, jwksURL: jwksURL, refresh: refresh, client: client})
		mu.Unlock()
		if shouldFail != nil {
			if err := shouldFail(jwksURL); err != nil {
				return nil, err
			}
		}
		return fakeKeyfuncStub{}, nil
	}
}

func newTestRegistry(t *testing.T, newKeyfunc newKeyfuncFunc) *Registry {
	t.Helper()
	r := NewRegistry(testLogger())
	t.Cleanup(r.Close)
	r.newKeyfunc = newKeyfunc
	return r
}

func jwtSourceNamed(name, jwksURL string) config.JWTSource {
	return config.JWTSource{Name: name, Issuer: "https://" + name + ".example.com", JWKSURL: jwksURL, JWKSCacheTTL: time.Minute}
}

func TestRegistry_Reconcile_SamePointerIsNoOp(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		JWT: []config.JWTSource{jwtSourceNamed("a", "https://a.example.com/jwks.json")},
	}}}

	for i := 0; i < 5; i++ {
		r.Reconcile(cfg)
	}

	r.mu.Lock()
	n := len(r.resolvers)
	r.mu.Unlock()
	assert.Equal(t, 1, n, "one resolver entry created regardless of repeated Reconcile calls on the same pointer")
}

func TestRegistry_Reconcile_ContentIdenticalNewPointer_NoEviction(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}

	r.Reconcile(cfg1)
	_, err := r.Keyfunc(t.Context(), src)
	require.NoError(t, err)

	r.Reconcile(cfg2) // different pointer, identical content/fingerprint

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "content-identical reconcile must not rebuild the resolver")
}

func TestRegistry_Reconcile_URLChanged_Rebuilds(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src1 := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src1}}}}
	r.Reconcile(cfg1)
	_, err := r.Keyfunc(t.Context(), src1)
	require.NoError(t, err)

	var firstCtx context.Context
	mu.Lock()
	firstCtx = calls[0].ctx
	mu.Unlock()

	src2 := src1
	src2.JWKSURL = "https://a.example.com/jwks-v2.json"
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src2}}}}
	r.Reconcile(cfg2)

	select {
	case <-firstCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the old resolver's context to be canceled on eviction")
	}

	_, err = r.Keyfunc(t.Context(), src2)
	require.NoError(t, err)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "URL change must trigger a rebuild")
}

func TestRegistry_Reconcile_TTLChanged_Rebuilds(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src1 := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src1}}}}
	r.Reconcile(cfg1)
	_, err := r.Keyfunc(t.Context(), src1)
	require.NoError(t, err)

	src2 := src1
	src2.JWKSCacheTTL = 5 * time.Minute
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src2}}}}
	r.Reconcile(cfg2)
	_, err = r.Keyfunc(t.Context(), src2)
	require.NoError(t, err)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "TTL change must trigger a rebuild even though the URL is unchanged")
}

func TestRegistry_Reconcile_SourceRemovedOrDisabled_Evicts(t *testing.T) {
	for _, mutate := range []struct {
		name   string
		mutate func(cfg *config.Config)
	}{
		{"removed", func(cfg *config.Config) { cfg.Inbound.Auth.JWT = nil }},
		{"disabled", func(cfg *config.Config) { cfg.Inbound.Auth.JWT[0].Disabled = true }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []fakeKeyfuncCall
			r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

			src := jwtSourceNamed("a", "https://a.example.com/jwks.json")
			cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
			r.Reconcile(cfg1)
			_, err := r.Keyfunc(t.Context(), src)
			require.NoError(t, err)

			cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
			mutate.mutate(cfg2)
			r.Reconcile(cfg2)

			r.mu.Lock()
			n := len(r.resolvers)
			r.mu.Unlock()
			assert.Equal(t, 0, n)
		})
	}
}

func TestRegistry_Reconcile_SourceRenamed_OldEvictedNewBuilt(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src1 := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src1}}}}
	r.Reconcile(cfg1)

	src2 := src1
	src2.Name = "a-renamed"
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src2}}}}
	r.Reconcile(cfg2)

	r.mu.Lock()
	_, oldPresent := r.resolvers["a"]
	_, newPresent := r.resolvers["a-renamed"]
	r.mu.Unlock()
	assert.False(t, oldPresent)
	assert.True(t, newPresent)
}

func TestRegistry_Reconcile_AllJWTRemovedWithSAMLRemaining_DoesNotPanic(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
	r.Reconcile(cfg1)

	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		SAML: &config.SAMLSource{Name: "saml-a", Issuer: "https://idp.example.com"},
	}}}
	assert.NotPanics(t, func() { r.Reconcile(cfg2) })

	r.mu.Lock()
	n := len(r.resolvers)
	r.mu.Unlock()
	assert.Equal(t, 0, n)
}

func TestRegistry_Close_CancelsEveryResolver(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := NewRegistry(testLogger())
	r.newKeyfunc = newFakeNewKeyfunc(&calls, &mu, nil)

	srcA := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	srcB := jwtSourceNamed("b", "https://b.example.com/jwks.json")
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{srcA, srcB}}}}
	r.Reconcile(cfg)
	_, err := r.Keyfunc(t.Context(), srcA)
	require.NoError(t, err)
	_, err = r.Keyfunc(t.Context(), srcB)
	require.NoError(t, err)

	mu.Lock()
	ctxs := []context.Context{calls[0].ctx, calls[1].ctx}
	mu.Unlock()

	r.Close()

	for _, ctx := range ctxs {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("expected Close to cancel every resolver's context")
		}
	}
}

func TestRegistry_Keyfunc_BuildFailureIsNegativelyCached(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	buildErr := errors.New("jwks unreachable")
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, func(string) error { return buildErr }))

	now := time.Now()
	r.now = func() time.Time { return now }
	r.retry = time.Minute

	src := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
	r.Reconcile(cfg)

	_, err1 := r.Keyfunc(t.Context(), src)
	require.Error(t, err1)
	_, err2 := r.Keyfunc(t.Context(), src)
	require.Error(t, err2)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "a second call within the retry window must not attempt another build")

	now = now.Add(2 * time.Minute) // advance past the retry window
	_, err3 := r.Keyfunc(t.Context(), src)
	require.Error(t, err3)

	mu.Lock()
	n = len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "a call after the retry window must attempt another build")
}

// TestRegistry_ConcurrentReconcileAndKeyfunc_Converges is primarily a
// -race target (exercised by `make test`, which runs with -race): many
// goroutines alternate Reconcile(cfgA)/Reconcile(cfgB)/Keyfunc(...)
// concurrently, per the design note on Reconcile's "eventually
// correct, not immediately correct" concurrency behavior. It also
// checks the one property that must still hold once the churn settles:
// the registry converges to whichever config was reconciled last.
func TestRegistry_ConcurrentReconcileAndKeyfunc_Converges(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	srcA := jwtSourceNamed("a", "https://a.example.com/jwks.json")
	srcB := jwtSourceNamed("b", "https://b.example.com/jwks.json")
	cfgA := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{srcA}}}}
	cfgB := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{srcB}}}}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				r.Reconcile(cfgA)
				_, _ = r.Keyfunc(t.Context(), srcA)
			} else {
				r.Reconcile(cfgB)
				_, _ = r.Keyfunc(t.Context(), srcB)
			}
		}(i)
	}
	wg.Wait()

	// Settle on cfgB and confirm the registry converges to exactly it,
	// regardless of whatever transient state the churn above left.
	r.Reconcile(cfgB)
	r.mu.Lock()
	_, hasA := r.resolvers["a"]
	_, hasB := r.resolvers["b"]
	r.mu.Unlock()
	assert.False(t, hasA)
	assert.True(t, hasB)
}

func TestRegistry_Keyfunc_OIDCDiscoverySource(t *testing.T) {
	idp := NewTestIDP(t)
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src := config.JWTSource{
		Name:             "a",
		Issuer:           idp.Issuer,
		OIDCDiscoveryURL: idp.DiscoveryURL,
		JWKSCacheTTL:     time.Minute,
	}
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}}
	r.Reconcile(cfg)

	_, err := r.Keyfunc(t.Context(), src)
	require.NoError(t, err)

	mu.Lock()
	got := calls[0].jwksURL
	mu.Unlock()
	assert.Equal(t, idp.JWKSURL, got, "discovery must resolve to the real jwks_uri before building the resolver")

	// A second call for the same (already-built) source doesn't re-run
	// discovery.
	_, err = r.Keyfunc(t.Context(), src)
	require.NoError(t, err)
	assert.Equal(t, 1, idp.DiscoveryHits())
}
