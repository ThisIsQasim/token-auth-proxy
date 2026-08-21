package authn

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// defaultResolverRetry is how long a failed resolver build (JWKS
// unreachable, or OIDC discovery failed) is negative-cached before the
// next attempt — keeps a down endpoint from becoming a per-request
// network hammer, and lets it self-heal on its own once it recovers,
// with no config change required.
const defaultResolverRetry = 30 * time.Second

// jwksHTTPTimeout bounds both discovery and JWKS fetches. Deliberately
// its own client, never the backend's transport (proxy.BuildTransport)
// — different endpoint, different trust decision, different timeout
// profile.
const jwksHTTPTimeout = 10 * time.Second

// newKeyfuncFunc builds a jwt.Keyfunc-producing resolver for jwksURL,
// refreshing on the given interval and fetching with client. A seam:
// production wires defaultNewKeyfunc; tests inject a deterministic fake
// so jwks_test.go can exercise Registry's lifecycle without any real
// network.
//
// client is a parameter rather than something the implementation
// captures because it varies per source: a source pinning a ca_cert
// gets its own client, everything else shares the registry's default
// one. See Registry.Keyfunc.
type newKeyfuncFunc func(ctx context.Context, jwksURL string, refresh time.Duration, client *http.Client) (keyfunc.Keyfunc, error)

// Registry owns one JWKS resolver per configured, non-Disabled JWT
// source, and the background refresh goroutine each resolver runs. It
// is reconciled lazily against the live config on every request via
// Reconcile — there is no subscribe-to-config-changes mechanism in
// config.Watcher (it's pure atomic-pointer publication; see
// proxy.New's Rewrite callback for the identical pull-based pattern
// already used elsewhere in this codebase), and adding one to serve
// this single consumer would be a larger change than reconciling here.
//
// Resolvers are keyed by source Name, not by JWKS URL: JWKSCacheTTL is
// per-source and baked into the resolver at construction, so two
// sources sharing a URL but different TTLs couldn't share a resolver
// anyway; and an oidc_discovery_url source's real JWKS URL isn't known
// without a network call, so keying by it would require I/O just to
// compute a map key. Name is already guaranteed unique by
// config.Validate, so it's a stable, zero-I/O key. The cost: two
// sources with identical jwks_url and jwks_cache_ttl get two resolvers
// (two goroutines, two caches) instead of one — a rare configuration,
// and correctness plus a lock-free lookup path are worth it.
type Registry struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger
	// client is the shared default, used by every source that doesn't
	// pin its own ca_cert. Sources that do get their own — see Keyfunc.
	client *http.Client
	retry  time.Duration
	now    func() time.Time

	newKeyfunc newKeyfuncFunc

	seen atomic.Pointer[config.Config]

	mu        sync.Mutex
	resolvers map[string]*resolver
}

// resolver holds the JWKS resolution state for one source, guarded by
// its own mutex — not the Registry's — held across the network I/O of
// building it, so a slow or hanging JWKS/discovery endpoint for one
// source can never block requests routed to a different source.
type resolver struct {
	name        string
	fingerprint string

	mu      sync.Mutex
	kf      keyfunc.Keyfunc
	cancel  context.CancelFunc
	jwksURL string
	lastErr error
	nextTry time.Time

	// client is whichever HTTP client this resolver was built with, and
	// ownClient records whether it belongs to this resolver alone (true
	// only when the source pins a ca_cert) or is the registry's shared
	// default. Only an owned client may be torn down on eviction.
	client    *http.Client
	ownClient bool
}

func (r *resolver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	if r.ownClient && r.client != nil {
		// This resolver built its own client — and so its own connection
		// pool — for a pinned CA. Nothing else can reuse those
		// connections once the resolver is gone, so drop them now
		// instead of waiting out the transport's IdleConnTimeout.
		r.client.CloseIdleConnections()
	}
}

// NewRegistry constructs a Registry. Call Close when done to stop every
// resolver's background refresh goroutine.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defaultClient := &http.Client{Timeout: jwksHTTPTimeout}

	return &Registry{
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
		client: defaultClient,
		retry:  defaultResolverRetry,
		now:    time.Now,
		newKeyfunc: func(ctx context.Context, jwksURL string, refresh time.Duration, client *http.Client) (keyfunc.Keyfunc, error) {
			return keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
				Client:          client,
				HTTPTimeout:     jwksHTTPTimeout,
				RefreshInterval: refresh,
				RefreshErrorHandlerFunc: func(u string) func(context.Context, error) {
					return func(_ context.Context, err error) {
						logger.Warn("failed to refresh jwks", "jwks_url", u, "err", err)
					}
				},
			})
		},
		resolvers: make(map[string]*resolver),
	}
}

// Close cancels every resolver's background refresh goroutine.
func (r *Registry) Close() {
	r.cancel()
}

// fingerprint identifies everything about a JWTSource a resolver is
// built from — a change to any of these (and only these) means the old
// resolver must be rebuilt, not reused.
//
// CACert is included as full PEM content, not as a digest: it's what
// the resolver's TLS trust roots were built from, so rotating the CA
// (typically by editing the file behind a "${file:...}" reference and
// touching the config) has to evict the resolver, or the old roots
// would stay live until some unrelated field changed. PEM is base64
// and can't contain the NUL separator.
func fingerprint(j config.JWTSource) string {
	return j.JWKSURL + "\x00" + j.OIDCDiscoveryURL + "\x00" + j.JWKSCacheTTL.String() + "\x00" + j.CACert
}

// newCACertClient builds an HTTP client that verifies TLS against
// exactly the CAs in caCertPEM; the system trust store is not consulted
// (see config.ParseCACertPool for why it replaces rather than extends).
//
// Cloned from http.DefaultTransport rather than assembled from scratch
// so that proxy support (HTTP_PROXY/HTTPS_PROXY/NO_PROXY), connection
// pooling limits and HTTP/2 negotiation stay identical to every other
// client here — the trust roots are the only intended difference.
func newCACertClient(caCertPEM string) (*http.Client, error) {
	pool, err := config.ParseCACertPool(caCertPEM)
	if err != nil {
		return nil, err
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	return &http.Client{Timeout: jwksHTTPTimeout, Transport: transport}, nil
}

// Reconcile brings the resolver set in line with cfg. In the steady
// state (cfg already reconciled) it's a single atomic load plus a
// pointer comparison: config.Watcher publishes a brand-new *Config
// pointer on every successful reload — even a content-identical one —
// and never mutates a published one, so pointer inequality is an exact,
// allocation-free "this might have changed" signal, and pointer
// equality is an exact "definitely didn't" one. No network I/O happens
// in Reconcile itself; it only creates unbuilt resolver placeholders
// and collects stale ones to evict.
//
// Concurrency note: two concurrent requests can call Reconcile against
// two different config pointers. Registry.mu serializes them, so the
// resolver map always ends up internally consistent with exactly one
// of the two calls — but seen might then briefly name the "loser."
// This is harmless and self-healing: the very next request's Reconcile
// call compares against the live config again and repairs it.
// Deliberately not solved with a generation counter or a CAS loop,
// which would add permanent bookkeeping to guard against a
// one-request transient.
func (r *Registry) Reconcile(cfg *config.Config) {
	if r.seen.Load() == cfg {
		return
	}

	desired := make(map[string]string, len(cfg.Inbound.Auth.JWT))
	for _, j := range cfg.Inbound.Auth.JWT {
		if j.Disabled {
			continue
		}
		desired[j.Name] = fingerprint(j)
	}

	r.mu.Lock()
	var stale []*resolver
	for name, res := range r.resolvers {
		if fp, ok := desired[name]; !ok || fp != res.fingerprint {
			stale = append(stale, res)
			delete(r.resolvers, name)
		}
	}
	for name, fp := range desired {
		if _, ok := r.resolvers[name]; !ok {
			r.resolvers[name] = &resolver{name: name, fingerprint: fp}
		}
	}
	// Store while still holding r.mu, atomically with the map mutation
	// above — not after Unlock. A racing Keyfunc self-heal (which also
	// mutates the map and seen together under r.mu) must never be able
	// to land in the window between Unlock and Store here: if it did,
	// its invalidating seen.Store(nil) would just get clobbered back to
	// cfg by this line, silently erasing the self-heal's signal that the
	// map drifted and a real Reconcile is still owed.
	r.seen.Store(cfg)
	r.mu.Unlock()

	for _, res := range stale {
		res.close()
		// jwksURL is guarded by res.mu (see the resolver struct comment),
		// same as kf/cancel/lastErr/nextTry — a Keyfunc call that looked
		// up this resolver just before Reconcile evicted it can still be
		// mid-build, writing jwksURL under res.mu, right up until this
		// point. Reading it here without the lock would race with that
		// write.
		res.mu.Lock()
		jwksURL := res.jwksURL
		res.mu.Unlock()
		r.logger.Info("evicted jwks resolver", "source", res.name, "jwks_url", jwksURL)
	}
}

// Keyfunc returns the jwt.Keyfunc for src, building the underlying
// resolver (and resolving an oidc_discovery_url to its jwks_uri) on
// first use. Concurrent callers for the same source serialize on that
// source's own mutex, so a burst of requests triggers exactly one
// build. A failed build is negative-cached for Registry.retry so a
// down JWKS/discovery endpoint doesn't become a per-request network
// hammer, and self-heals on the next request after the window without
// needing a config change.
func (r *Registry) Keyfunc(ctx context.Context, src config.JWTSource) (jwt.Keyfunc, error) {
	fp := fingerprint(src)

	r.mu.Lock()
	res, ok := r.resolvers[src.Name]
	var stale *resolver
	if !ok || res.fingerprint != fp {
		// Reconcile hasn't caught up yet (or wasn't called) — self-heal
		// the single entry rather than erroring; Reconcile will still
		// evict/rebuild it properly on its next pass. If an entry is
		// being *replaced* here (not just created), its background
		// refresh goroutine must still be canceled — Reconcile's own
		// eviction path already does this, and self-heal overwriting
		// the map entry without it would silently leak that goroutine
		// (polling the old/rotated-away JWKS URL) until Registry.Close
		// at process shutdown.
		if ok {
			stale = res
		}
		res = &resolver{name: src.Name, fingerprint: fp}
		r.resolvers[src.Name] = res

		// This mutates r.resolvers outside of Reconcile, so it must
		// invalidate seen: otherwise a racing Reconcile call that already
		// observed (and pointer-cached) this exact cfg — from before this
		// self-heal ran — would fast-path past its own diff next time it's
		// called with that same pointer, permanently missing the eviction
		// this entry needs (e.g. src.Name was evicted by a concurrent
		// Reconcile for a newer config, then resurrected here by a caller
		// still holding the old src). Forcing the next Reconcile to
		// actually recompute is what lets the registry converge.
		r.seen.Store(nil)
	}
	r.mu.Unlock()
	if stale != nil {
		stale.close()
	}

	res.mu.Lock()
	defer res.mu.Unlock()

	if res.kf != nil {
		return res.kf.KeyfuncCtx(ctx), nil
	}
	if r.now().Before(res.nextTry) {
		return nil, res.lastErr
	}

	// The client is chosen per source, not per registry: a source
	// pinning a ca_cert needs its own TLS trust roots, and therefore its
	// own transport and connection pool. Chosen here, on the build path,
	// so it costs nothing on the cached-resolver fast path above, and is
	// stored on res so close() can tear it down on eviction.
	client, ownClient := r.client, false
	if src.CACert != "" {
		c, err := newCACertClient(src.CACert)
		if err != nil {
			// config.Validate already parsed this exact PEM at load
			// time, so this is only reachable for a source that never
			// went through it. Negative-cached like any other build
			// failure rather than retried per request.
			res.lastErr = fmt.Errorf("build ca_cert trust roots: %w", err)
			res.nextTry = r.now().Add(r.retry)
			return nil, res.lastErr
		}
		client, ownClient = c, true
	}
	// An owned client is only worth keeping if the build below actually
	// succeeds. On every failure path it's dropped unreferenced, so its
	// idle connections would otherwise linger until IdleConnTimeout with
	// nothing able to reuse them — and the negative-cache retry builds a
	// fresh client each time it fires.
	built := false
	if ownClient {
		defer func() {
			if !built {
				client.CloseIdleConnections()
			}
		}()
	}

	jwksURL := src.JWKSURL
	if jwksURL == "" {
		// Bounded by the registry's own context + jwksHTTPTimeout, not
		// the caller's ctx — a successful discovery fetch is cached
		// under res and reused by every subsequent request for this
		// source, so one client disconnecting mid-fetch must not
		// poison that cache with a context-canceled error (and its
		// negative-cache window) for every other, perfectly healthy,
		// concurrent caller of the same source. Mirrors
		// SAMLRegistry.fetchAndBuild's identical rationale.
		discoveryCtx, cancel := context.WithTimeout(r.ctx, jwksHTTPTimeout)
		u, err := fetchJWKSURI(discoveryCtx, client, src.OIDCDiscoveryURL, src.Issuer)
		cancel()
		if err != nil {
			res.lastErr = fmt.Errorf("resolve oidc discovery: %w", err)
			res.nextTry = r.now().Add(r.retry)
			return nil, res.lastErr
		}
		jwksURL = u
	}

	resolverCtx, cancel := context.WithCancel(r.ctx)
	kf, err := r.newKeyfunc(resolverCtx, jwksURL, src.JWKSCacheTTL, client)
	if err != nil {
		cancel()
		res.lastErr = fmt.Errorf("build jwks resolver: %w", err)
		res.nextTry = r.now().Add(r.retry)
		return nil, res.lastErr
	}

	res.kf = kf
	res.cancel = cancel
	res.jwksURL = jwksURL
	res.client = client
	res.ownClient = ownClient
	res.lastErr = nil
	built = true
	r.logger.Info("built jwks resolver", "source", src.Name, "jwks_url", jwksURL, "pinned_ca", ownClient)

	return res.kf.KeyfuncCtx(ctx), nil
}
