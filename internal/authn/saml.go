package authn

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// defaultSAMLRetry mirrors defaultResolverRetry: how long a failed
// first-ever provider build (IdP metadata unreachable, or malformed) is
// negative-cached before the next attempt.
const defaultSAMLRetry = 30 * time.Second

// samlHTTPTimeout bounds IdP metadata fetches. Its own client, same
// rationale as jwksHTTPTimeout: a different endpoint, a different
// trust decision, a different timeout profile than the backend's own
// transport.
const samlHTTPTimeout = 10 * time.Second

// samlSessionSigningKeyMinLen mirrors config's minSessionSigningKeyLen
// (unexported there, so not directly reusable) — re-checked here at
// build time so a rebuild triggered by an unrelated config change
// doesn't silently proceed with an empty or weakened secret if
// whatever set the env var changed between config-load-time validation
// and now.
const samlSessionSigningKeyMinLen = 32

// newSAMLProviderFunc builds a samlsp.Middleware from src and
// already-fetched, already-validated IdP metadata. A seam: production
// wires buildSAMLProvider; tests inject a deterministic fake so
// saml_test.go can exercise SAMLRegistry's lifecycle without any real
// network or XML-DSig machinery.
type newSAMLProviderFunc func(src config.SAMLSource, idpMetadata *saml.EntityDescriptor) (*samlsp.Middleware, error)

// SAMLRegistry owns the single built samlsp.Middleware for the
// configured SAMLSource, if any, reconciled lazily against the live
// config on every request — the same pull-based pattern as Registry
// (see its doc comment for why: config.Watcher has no
// subscribe-to-changes mechanism), but simpler: InboundAuthConfig
// allows at most one SAMLSource to ever exist, so there's no map, no
// per-entry mutex, and no background refresh goroutine. samlsp has
// nothing equivalent to keyfunc's self-refreshing background client —
// IdP metadata freshness is checked on demand against
// SAMLSource.IDPMetadataCacheTTL inside Provider, not on a timer.
type SAMLRegistry struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger
	client *http.Client
	retry  time.Duration
	now    func() time.Time

	newProvider newSAMLProviderFunc

	seen atomic.Pointer[config.Config]

	// mu guards every field below, held across the metadata-fetch I/O
	// in Provider — unlike Registry's split Registry.mu/resolver.mu,
	// one mutex is enough here because there is only ever one entry to
	// guard, so there's nothing a slow fetch could block except a
	// concurrent caller for that same single entry (which should
	// serialize anyway, so a burst of concurrent requests triggers
	// exactly one fetch, not N).
	mu          sync.Mutex
	fingerprint string
	provider    *samlsp.Middleware
	metadataAt  time.Time // when provider's IdP metadata was last (re)fetched
	lastErr     error
	nextTry     time.Time
}

// NewSAMLRegistry constructs a SAMLRegistry. Call Close when done.
func NewSAMLRegistry(logger *slog.Logger) *SAMLRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &SAMLRegistry{
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
		client:      &http.Client{Timeout: samlHTTPTimeout},
		retry:       defaultSAMLRetry,
		now:         time.Now,
		newProvider: buildSAMLProvider,
	}
}

// Close cancels any in-flight metadata fetch bound to the registry's
// own context (see Provider's doc comment for why fetches are bound to
// this, not the request's, context).
func (r *SAMLRegistry) Close() {
	r.cancel()
}

// samlFingerprint identifies everything about a SAMLSource a provider
// is built from — a change to any of these (and only these) means the
// old provider must be rebuilt, not reused. Deliberately excludes the
// *resolved values* of SessionSigningKeyEnv and SPKeyEnv (only the env
// var names are config; the secret/key content behind them isn't) — a
// secret or SP-key rotation via the env var's underlying value, with no
// accompanying config change, won't trigger a rebuild, matching
// JWTSource's fingerprint, which likewise never includes
// fetched/resolved material, only configured trust parameters. SPCert
// is different: it's PEM content directly in config (not a name
// pointing at something else), so it — and SPKeyEnv's name, matching
// SessionSigningKeyEnv's treatment — must be included, or rotating to a
// new sp_key_env/sp_cert pair (or adding/removing them) wouldn't take
// effect until the next unrelated rebuild (e.g. IDPMetadataCacheTTL
// expiry).
func samlFingerprint(s config.SAMLSource) string {
	return strings.Join([]string{
		s.Issuer,
		strings.Join(s.Audiences, ","),
		s.IDPMetadataURL,
		s.IDPMetadataCacheTTL.String(),
		s.SPBaseURL,
		s.SPEntityID,
		s.ACSPath,
		s.SessionCookie,
		s.SessionSigningKeyEnv,
		s.SessionDuration.String(),
		s.SPKeyEnv,
		s.SPCert,
	}, "\x00")
}

// Reconcile brings the registry's single entry in line with cfg. In
// the steady state it's a single atomic load plus a pointer comparison
// — see Registry.Reconcile's identical doc comment for the full
// rationale (config.Watcher's pointer-publication contract, and the
// "briefly names the loser, self-heals next call" concurrency note,
// both apply here unchanged).
func (r *SAMLRegistry) Reconcile(cfg *config.Config) {
	if r.seen.Load() == cfg {
		return
	}

	var fp string
	if cfg.Inbound.Auth.SAMLEnabled() {
		fp = samlFingerprint(*cfg.Inbound.Auth.SAML)
	}

	r.mu.Lock()
	if fp != r.fingerprint {
		if r.provider != nil {
			r.logger.Info("evicted saml provider")
		}
		r.provider = nil
		r.lastErr = nil
		r.nextTry = time.Time{}
		r.fingerprint = fp
	}
	r.mu.Unlock()

	r.seen.Store(cfg)
}

// Provider returns the samlsp.Middleware for src, building it (and
// fetching IdP metadata) on first use. Concurrent callers serialize on
// r.mu, so a burst of requests triggers exactly one fetch. A failed
// first-ever build is negative-cached for SAMLRegistry.retry, same
// rationale as Registry.Keyfunc's identical negative caching.
//
// Deliberately takes no context: nothing in the returned Middleware is
// meant to be scoped to the calling request, and the metadata fetch
// itself is always bound to the registry's own context (with a
// samlHTTPTimeout ceiling), never the caller's — a successful fetch is
// cached and reused by every subsequent request regardless of which
// source, so one client disconnecting mid-fetch must not abort it for
// everyone else waiting on the same result.
func (r *SAMLRegistry) Provider(src config.SAMLSource) (*samlsp.Middleware, error) {
	fp := samlFingerprint(src)

	r.mu.Lock()
	defer r.mu.Unlock()

	if fp != r.fingerprint {
		// Reconcile hasn't caught up yet (or wasn't called) — self-heal,
		// matching Registry.Keyfunc's identical rationale.
		r.fingerprint = fp
		r.provider = nil
		r.lastErr = nil
		r.nextTry = time.Time{}
	}

	if r.provider != nil {
		if r.now().Before(r.metadataAt.Add(src.IDPMetadataCacheTTL)) {
			return r.provider, nil
		}

		// Metadata's gone stale — refresh it, but fail open: an
		// already-working provider keeps serving on a refresh failure
		// rather than logging out every active session over a
		// transient IdP blip. Deliberately asymmetric with the
		// first-build path below, which fails closed. See
		// buildSAMLProvider's doc comment for the same asymmetry
		// stated from the config-schema side.
		provider, err := r.fetchAndBuild(src)
		if err != nil {
			r.logger.Warn("failed to refresh saml idp metadata; continuing to serve the previous provider", "err", err)
			// Reset the clock so this doesn't retry on every single
			// request during an outage — one attempt per TTL window.
			r.metadataAt = r.now()
			return r.provider, nil
		}
		r.provider = provider
		r.metadataAt = r.now()
		r.logger.Info("refreshed saml provider")
		return r.provider, nil
	}

	// No provider yet: fail closed, same as Registry.Keyfunc's negative
	// caching for a first-ever build failure — there is no sensible
	// degraded behavior when we've never had a working SSO URL or
	// signing cert to begin with.
	if r.now().Before(r.nextTry) {
		return nil, r.lastErr
	}

	provider, err := r.fetchAndBuild(src)
	if err != nil {
		r.lastErr = err
		r.nextTry = r.now().Add(r.retry)
		return nil, r.lastErr
	}

	r.provider = provider
	r.metadataAt = r.now()
	r.lastErr = nil
	r.logger.Info("built saml provider", "idp_metadata_url", src.IDPMetadataURL)

	return r.provider, nil
}

// fetchAndBuild fetches src's IdP metadata (bounded by the registry's
// own context and samlHTTPTimeout, never the caller's — see Provider's
// doc comment) and builds a provider from it. buildSAMLProvider itself
// is a pure function of (src, idpMetadata) with no logger of its own
// (keeps it independently testable, and keeps newSAMLProviderFunc's
// test seam simple — see saml_test.go's fake) — OnError is wired here
// instead, once per build, using the registry's own logger, so every
// ACS/assertion failure is bridged to structured slog logging (see
// samlOnError's doc comment) rather than samlsp's default
// unstructured log.Printf.
func (r *SAMLRegistry) fetchAndBuild(src config.SAMLSource) (*samlsp.Middleware, error) {
	fetchCtx, cancel := context.WithTimeout(r.ctx, samlHTTPTimeout)
	defer cancel()

	entity, err := fetchIDPMetadata(fetchCtx, r.client, src.IDPMetadataURL, src.Issuer)
	if err != nil {
		return nil, fmt.Errorf("fetch idp metadata: %w", err)
	}

	provider, err := r.newProvider(src, entity)
	if err != nil {
		return nil, fmt.Errorf("build saml provider: %w", err)
	}
	provider.OnError = samlOnError(r.logger)

	// main.go warns about this too, but only once, from the config
	// snapshot at process startup — a SAML source hot-added or
	// hot-edited later never re-triggers that check. Providers are
	// built lazily (on first request needing one, not eagerly at
	// startup), so warning here as well is what actually catches an
	// insecure sp_base_url introduced via hot-reload after the process
	// has been running for a while.
	if !strings.HasPrefix(src.SPBaseURL, "https://") {
		r.logger.Warn("saml sp_base_url is not https: real browsers will not send the ACS tracking cookie back cross-site, so login will not work outside local dev/test",
			"sp_base_url", src.SPBaseURL)
	}

	return provider, nil
}

// buildSAMLProvider is the production newSAMLProviderFunc.
//
// Options.Key/Certificate are nil unless SPKeyEnv/SPCert are
// configured — with neither set (the default), this proxy has no
// persistent SP identity at all beyond its entity ID: no signing, no
// encryption, and critically, saml.ServiceProvider.Metadata never
// emits an "encryption" KeyDescriptor, so a real IdP that fetches this
// SP's metadata has nothing to encrypt to and sends plaintext
// assertions instead. Configuring SPKeyEnv/SPCert flips that: the IdP
// sees an encryption KeyDescriptor and (if it chooses to) sends
// EncryptedAssertion elements, which sp.ParseResponse then decrypts
// transparently using this same key — see the README's SAML section
// for exactly which real-world IdPs this now unblocks (and which
// requirement — signed AuthnRequests, still unsupported — it doesn't).
// SignRequest itself is never set here, so signed AuthnRequests remain
// off regardless: the two capabilities are independent in samlsp, and
// this pass only turns on decryption.
//
// samlsp.New hardcodes the ACS URL as "saml/acs" relative to
// Options.URL, so it's overwritten afterward with the operator-chosen
// ACSPath. The default session/tracked-request codecs are replaced
// with the symmetric HS256 codecs in saml_session.go, keyed by
// SessionSigningKeyEnv's value, so that config field — not the SP
// keypair above, which serves a different purpose — is what governs
// the session mechanism.
func buildSAMLProvider(src config.SAMLSource, idpMetadata *saml.EntityDescriptor) (*samlsp.Middleware, error) {
	spBase, err := url.Parse(src.SPBaseURL)
	if err != nil {
		// config.Validate already checked this parses as an absolute
		// http(s) URL; a failure here means something re-set the env
		// between validation and this build.
		return nil, fmt.Errorf("parse sp_base_url: %w", err)
	}

	secret, ok := os.LookupEnv(src.SessionSigningKeyEnv)
	if !ok {
		return nil, fmt.Errorf("session_signing_key_env: environment variable %q is not set", src.SessionSigningKeyEnv)
	}
	if len(secret) < samlSessionSigningKeyMinLen {
		return nil, fmt.Errorf("session_signing_key_env: environment variable %q must be at least %d bytes, got %d",
			src.SessionSigningKeyEnv, samlSessionSigningKeyMinLen, len(secret))
	}

	opts := samlsp.Options{
		EntityID:    src.SPEntityID,
		URL:         *spBase,
		IDPMetadata: idpMetadata,
	}
	if src.SPKeyEnv != "" {
		keyPEM, ok := os.LookupEnv(src.SPKeyEnv)
		if !ok {
			return nil, fmt.Errorf("sp_key_env: environment variable %q is not set", src.SPKeyEnv)
		}
		key, err := config.ParseSPPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("sp_key_env: environment variable %q: %w", src.SPKeyEnv, err)
		}
		cert, err := config.ParseSPCertificate(src.SPCert)
		if err != nil {
			return nil, fmt.Errorf("sp_cert: %w", err)
		}
		opts.Key = key
		opts.Certificate = cert
	}

	mw, err := samlsp.New(opts)
	if err != nil {
		return nil, fmt.Errorf("construct samlsp middleware: %w", err)
	}

	acsURL := *spBase
	acsURL.Path = src.ACSPath
	mw.ServiceProvider.AcsURL = acsURL

	if len(src.Audiences) > 0 {
		audiences := append([]string(nil), src.Audiences...)
		spEntityID := src.SPEntityID
		mw.ServiceProvider.ValidateAudienceRestriction = func(assertion *saml.Assertion) error {
			return validateSAMLAudienceRestriction(assertion, spEntityID, audiences)
		}
	}

	https := spBase.Scheme == "https"

	now := time.Now
	mw.Session = samlsp.CookieSessionProvider{
		Name: src.SessionCookie,
		// samlsp.CookieRequestTracker (the tracker cookie below) hardcodes
		// HttpOnly: true internally; CookieSessionProvider has no such
		// default (its zero value is false), so it must be set explicitly
		// here — otherwise the session cookie, which carries the signed
		// session JWT, would be readable by any script on the origin.
		HTTPOnly: true,
		Secure:   https,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   src.SessionDuration,
		Codec: samlSessionCodec{
			secret:   []byte(secret),
			audience: src.SPEntityID,
			issuer:   src.SPEntityID,
			maxAge:   src.SessionDuration,
			now:      now,
		},
	}

	// The IdP posts the assertion back via a cross-site POST to the ACS
	// path. http.SameSiteDefaultMode emits no SameSite attribute at
	// all, so browsers fall back to their own default (Lax), which
	// blocks cookies on a cross-site POST — this cookie must be None,
	// which browsers only honor when Secure is also set (hence https).
	// A plain-http SPBaseURL therefore breaks real-browser login; see
	// main.go's startup warning.
	trackerSameSite := http.SameSiteLaxMode
	if https {
		trackerSameSite = http.SameSiteNoneMode
	}
	mw.RequestTracker = samlsp.CookieRequestTracker{
		ServiceProvider: &mw.ServiceProvider,
		NamePrefix:      "saml_",
		MaxAge:          saml.MaxIssueDelay,
		SameSite:        trackerSameSite,
		Codec: samlTrackedRequestCodec{
			secret:   []byte(secret),
			audience: src.SPEntityID,
			issuer:   src.SPEntityID,
			maxAge:   saml.MaxIssueDelay,
			now:      now,
		},
	}

	return mw, nil
}

// validateSAMLAudienceRestriction is the production
// ServiceProvider.ValidateAudienceRestriction hook, installed only
// when SAMLSource.Audiences is non-empty. It accepts the assertion iff
// the assertion has no AudienceRestrictions at all (matching
// saml.ServiceProvider's own default, unauthenticated-by-omission
// behavior), or at least one restriction names either the SP's own
// entity ID or one of the configured extra audiences — a superset of
// the library's default (which only ever accepts the SP's own entity
// ID), mirroring how JWTSource.Audiences widens acceptance rather than
// narrowing it.
func validateSAMLAudienceRestriction(assertion *saml.Assertion, spEntityID string, extra []string) error {
	if assertion.Conditions == nil || len(assertion.Conditions.AudienceRestrictions) == 0 {
		return nil
	}

	for _, ar := range assertion.Conditions.AudienceRestrictions {
		if ar.Audience.Value == spEntityID {
			return nil
		}
		for _, a := range extra {
			if ar.Audience.Value == a {
				return nil
			}
		}
	}
	return fmt.Errorf("assertion audience restriction does not contain %q or any configured audience", spEntityID)
}
