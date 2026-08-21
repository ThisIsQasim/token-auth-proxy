package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// basicCacheTTL is how long a successfully verified credential is
// remembered, so a client making many requests pays bcrypt's cost once
// rather than per request.
//
// This is not a revocation window: removing a user (or changing any
// hash) changes the source's fingerprint, which drops the whole cache
// on the next Reconcile — see basicFingerprint. The TTL only bounds how
// long an entry can occupy memory and how stale a still-configured
// credential's verification may be, so there's no reason to make it an
// operator-facing knob.
const basicCacheTTL = 5 * time.Minute

// basicNegativeCacheTTL is the (much shorter) window a *failed*
// credential is remembered for. It exists to stop a client retrying the
// same wrong password in a loop from costing a full bcrypt compare every
// time; short, because unlike a success there's no reason to trust it
// for long. Kept in a separate, smaller map from the successes so a
// flood of wrong passwords can't evict entries a legitimate client
// depends on.
const basicNegativeCacheTTL = 30 * time.Second

// Cache capacities. Reaching one clears that map wholesale rather than
// evicting a victim entry: with no access-recency tracked, any
// individual choice would be arbitrary, and Go's map iteration order is
// deliberately undefined, so "drop it all and re-verify" is the only
// policy that can be described honestly in a comment. Both are far
// larger than any plausible configured user count — they bound
// *credentials seen*, not users.
const (
	maxBasicCacheEntries         = 4096
	maxBasicNegativeCacheEntries = 1024
)

// maxBasicCredentialLen bounds the decoded "user:pass" this package
// will even attempt to verify. bcrypt ignores everything past 72 bytes
// anyway; this just keeps an absurdly long header from doing pointless
// work first.
const maxBasicCredentialLen = 1024

// maxLoggedUsernameLen bounds how much of an attacker-controlled
// username reaches a log field, mirroring maxLoggedIssuerLen.
const maxLoggedUsernameLen = 128

// basicVerifyTimeout is how long a request will wait for a bcrypt slot
// before being turned away with a 503. See BasicRegistry.sem.
const basicVerifyTimeout = 5 * time.Second

// errBasicSaturated is returned when the bcrypt semaphore stayed full
// for basicVerifyTimeout. Distinct from a credential failure: the
// caller turns it into a 503, not a 401.
var errBasicSaturated = errors.New("basic auth verification is saturated")

// compareHashFunc is a seam over bcrypt.CompareHashAndPassword:
// production wires bcrypt itself, tests inject a counting fake so
// basic_test.go can assert *how many* compares actually happened (i.e.
// that the cache works) without timing anything.
type compareHashFunc func(hash, password []byte) error

// BasicRegistry verifies HTTP Basic credentials against the configured
// BasicSource, caching successful verifications.
//
// The cache is the reason this type exists at all. bcrypt is
// intentionally slow — tens to hundreds of milliseconds per compare,
// scaling with the hash's cost factor — and unlike a JWT signature
// check (microseconds, and the token carries its own expiry) a Basic
// credential is re-presented, and would be re-verified, on every single
// request: one browser page load with twenty subresources would pay it
// twenty times. Caching the verified result turns that back into one.
//
// Reconciled lazily against the live config on every request, exactly
// like Registry and SAMLRegistry — see Registry.Reconcile's doc comment
// for why the pull-based pattern is used rather than subscribing to
// config changes. There is no Close: unlike those two, this owns no
// goroutine, context or network client, so there is nothing to tear
// down and a no-op Close for symmetry would just be dead code.
type BasicRegistry struct {
	logger *slog.Logger
	now    func() time.Time

	compareHash compareHashFunc

	// verifyTimeout is how long a request waits for a sem slot before
	// being turned away. A field rather than a bare constant so tests
	// can drive the saturation path without sleeping, matching the
	// now/retry seams on the other registries.
	verifyTimeout time.Duration

	// sem bounds how many bcrypt compares can run at once. Without it,
	// unauthenticated requests carrying wrong passwords are a remote CPU
	// exhaustion vector: each one occupies a core for the duration of a
	// compare, and enough concurrent ones starve the proxying path
	// itself, not merely the auth path. The success cache is no defense
	// here — an attacker never presents a credential worth caching.
	sem chan struct{}

	// cacheKey keys the caches under a per-process random secret. An
	// HMAC rather than a bare digest because the value being keyed
	// includes the presented *plaintext* password: a plain SHA-256 of
	// one, recovered from a heap dump or core file, is brute-forceable
	// offline in seconds, while an HMAC under an ephemeral key is not.
	// Same cost, strictly better failure mode.
	cacheKey []byte

	seen atomic.Pointer[config.Config]

	mu          sync.Mutex
	fingerprint string
	cache       map[string]time.Time
	negative    map[string]time.Time
}

// NewBasicRegistry constructs a BasicRegistry. There is deliberately no
// matching Close — see the type's doc comment.
func NewBasicRegistry(logger *slog.Logger) *BasicRegistry {
	if logger == nil {
		logger = slog.Default()
	}

	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand.Read never returns an error on any platform this
		// builds for; if that ever changed, falling back to an
		// unkeyed cache would silently weaken it, so fail loudly.
		panic("authn: cannot read random bytes for the basic auth cache key: " + err.Error())
	}

	// Half the CPUs, at least one: enough to use the machine, while
	// leaving room for the proxying path to keep running under an auth
	// flood.
	slots := max(runtime.NumCPU()/2, 1)

	return &BasicRegistry{
		logger:        logger,
		now:           time.Now,
		compareHash:   bcrypt.CompareHashAndPassword,
		verifyTimeout: basicVerifyTimeout,
		sem:           make(chan struct{}, slots),
		cacheKey:      key,
		cache:         make(map[string]time.Time),
		negative:      make(map[string]time.Time),
	}
}

// basicFingerprint identifies everything a verification result depends
// on. A change to any of it — a user added or removed, a password
// rotated, the realm changed — invalidates every cached result, which
// is what makes the cache safe: revocation happens on config change,
// not on TTL expiry.
func basicFingerprint(b config.BasicSource) string {
	parts := make([]string, 0, len(b.Users)*2+1)
	parts = append(parts, b.Realm)
	for _, u := range b.Users {
		parts = append(parts, u.Username, u.PasswordHash)
	}
	return strings.Join(parts, "\x00")
}

// Reconcile brings the registry in line with cfg. In the steady state
// it's a single atomic load plus a pointer comparison — see
// Registry.Reconcile's doc comment for the full rationale behind the
// pointer-publication contract this relies on.
//
// The pointer check alone isn't enough to gate the cache on: Watcher
// publishes a *new* Config pointer on every successful reload, and
// reloads fire on any event in the config directory — including
// unrelated files in a Kubernetes ConfigMap mount. Dropping the cache
// on every such event would re-expose the full bcrypt cost for no
// reason, which is exactly what the fingerprint prevents.
func (r *BasicRegistry) Reconcile(cfg *config.Config) {
	if r.seen.Load() == cfg {
		return
	}

	var fp string
	if cfg.Inbound.Auth.BasicEnabled() {
		fp = basicFingerprint(*cfg.Inbound.Auth.Basic)
	}

	r.mu.Lock()
	if fp != r.fingerprint {
		if len(r.cache) > 0 {
			r.logger.Info("basic auth config changed, dropped verified credential cache")
		}
		r.fingerprint = fp
		r.cache = make(map[string]time.Time)
		r.negative = make(map[string]time.Time)
	}
	r.mu.Unlock()

	r.seen.Store(cfg)
}

// Verify reports whether username/password match a user in src.
//
// It returns errBasicSaturated (and only that error) when every bcrypt
// slot stayed busy past basicVerifyTimeout; every other outcome is the
// boolean. A verification failure is never an error here — "wrong
// password" is an ordinary result, not a malfunction.
func (r *BasicRegistry) Verify(src config.BasicSource, username, password string) (bool, error) {
	if len(username)+len(password) > maxBasicCredentialLen {
		return false, nil
	}

	fp := basicFingerprint(src)
	key := r.key(fp, username, password)

	if ok, cached := r.lookup(key); cached {
		return ok, nil
	}

	hash, known := hashFor(src, username)
	if !known {
		// An unknown username still pays for a compare, against a real
		// configured hash, so that response time doesn't reveal which
		// usernames exist. Using a configured hash rather than a
		// hardcoded dummy one keeps the work automatically cost-matched
		// to this deployment's actual hashes — a dummy at the wrong
		// cost factor would leak the very thing this closes. The result
		// is discarded: a "successful" compare here is still a failure.
		hash = anyHash(src)
	}
	if hash == "" {
		// No users at all. config.Validate rejects that, so this is
		// unreachable via a loaded config; deny rather than trust it.
		return false, nil
	}

	ok, err := r.compare(hash, password)
	if err != nil {
		return false, err
	}
	ok = ok && known

	r.store(key, ok)
	return ok, nil
}

// key derives a cache key from the source fingerprint and the presented
// credential. The fingerprint is mixed in so an entry can never outlive
// the configuration it was verified against, even if Reconcile hasn't
// run yet; the credential is hashed as a single delimited value so that
// ("ab", "c") and ("a", "bc") can't collide.
func (r *BasicRegistry) key(fingerprint, username, password string) string {
	mac := hmac.New(sha256.New, r.cacheKey)
	mac.Write([]byte(fingerprint))
	mac.Write([]byte{0})
	mac.Write([]byte(username))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	return string(mac.Sum(nil))
}

// lookup returns a cached verification result for key, if one is live.
// Expiry is checked here, on read, rather than by a background sweeper:
// there's no goroutine to own one, and an expired entry costs nothing
// until it's looked at.
func (r *BasicRegistry) lookup(key string) (ok, cached bool) {
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if exp, found := r.cache[key]; found {
		if now.Before(exp) {
			return true, true
		}
		delete(r.cache, key)
	}
	if exp, found := r.negative[key]; found {
		if now.Before(exp) {
			return false, true
		}
		delete(r.negative, key)
	}
	return false, false
}

// store records a verification result.
func (r *BasicRegistry) store(key string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ok {
		if len(r.cache) >= maxBasicCacheEntries {
			r.cache = make(map[string]time.Time)
		}
		r.cache[key] = r.now().Add(basicCacheTTL)
		return
	}

	if len(r.negative) >= maxBasicNegativeCacheEntries {
		r.negative = make(map[string]time.Time)
	}
	r.negative[key] = r.now().Add(basicNegativeCacheTTL)
}

// compare runs one bcrypt comparison, holding a semaphore slot for its
// duration.
func (r *BasicRegistry) compare(hash, password string) (bool, error) {
	timer := time.NewTimer(r.verifyTimeout)
	defer timer.Stop()

	select {
	case r.sem <- struct{}{}:
	case <-timer.C:
		return false, errBasicSaturated
	}
	defer func() { <-r.sem }()

	err := r.compareHash([]byte(hash), []byte(password))
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		// A malformed hash (too short, bad cost, unknown prefix) can
		// only mean a configured hash got past config validation, so
		// it's worth an operator-visible log — but it's still just a
		// failed verification to the caller, never a 500.
		r.logger.Warn("basic auth hash could not be compared", "err", err)
	}
	return false, nil
}

// hashFor returns the configured hash for username, if that user
// exists. The username match is constant-time: it runs before any
// bcrypt work, so a byte-by-byte early exit here would be a timing
// oracle for usernames even though the compare below is padded.
func hashFor(src config.BasicSource, username string) (string, bool) {
	var (
		hash  string
		known bool
	)
	for _, u := range src.Users {
		if subtle.ConstantTimeCompare([]byte(u.Username), []byte(username)) == 1 {
			hash, known = u.PasswordHash, true
		}
	}
	return hash, known
}

// anyHash returns the first configured hash, used as the padding
// comparison for an unknown username. See Verify.
func anyHash(src config.BasicSource) string {
	if len(src.Users) == 0 {
		return ""
	}
	return src.Users[0].PasswordHash
}
