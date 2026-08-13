package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// Key generation is real crypto work (RSA-2048 keygen measured at
// ~300ms in CI) — cached once per process so every test using the
// default (non-rotated) TestIDP keypair doesn't pay for it separately.
// Rotate always generates a genuinely fresh keypair, deliberately not
// using these, since a rotation test needs the "before" and "after"
// keys to actually differ.
//
// Sharp edge this creates: two independent NewTestIDP(t) calls (same
// algorithm, neither Rotated) share the exact same underlying key —
// they're both convenience wrappers around the one cached keypair, not
// two distinct identities. That's fine for tests that only care about
// issuer/routing behavior, but a test asserting something is rejected
// specifically because it was signed under a *different* key (e.g.
// TestVerify_WrongSigningKey) must call Rotate on one of the two IDPs
// first, or the "different" key won't actually be different.
var (
	sharedRSAKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 2048)
	})
	sharedECKey = sync.OnceValues(func() (*ecdsa.PrivateKey, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
)

// idpKeypair bundles everything needed to both mint tokens (method +
// private key) and serve a JWKS document (kid + alg + public key).
type idpKeypair struct {
	kid    string
	alg    jwkset.ALG
	method jwt.SigningMethod
	priv   any
	pub    any
}

func newKeypair(tb testing.TB, kid string, es256, fresh bool) idpKeypair {
	tb.Helper()
	if es256 {
		var (
			priv *ecdsa.PrivateKey
			err  error
		)
		if fresh {
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else {
			priv, err = sharedECKey()
		}
		require.NoError(tb, err)
		return idpKeypair{kid: kid, alg: jwkset.AlgES256, method: jwt.SigningMethodES256, priv: priv, pub: &priv.PublicKey}
	}

	var (
		priv *rsa.PrivateKey
		err  error
	)
	if fresh {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		priv, err = sharedRSAKey()
	}
	require.NoError(tb, err)
	return idpKeypair{kid: kid, alg: jwkset.AlgRS256, method: jwt.SigningMethodRS256, priv: priv, pub: &priv.PublicKey}
}

// idpOptions configures NewTestIDP.
type idpOptions struct {
	es256  bool
	issuer string
	kid    string
}

// IDPOption customizes a TestIDP at construction.
type IDPOption func(*idpOptions)

// WithES256 mints an ES256/P-256 keypair instead of the default RS256.
func WithES256() IDPOption { return func(o *idpOptions) { o.es256 = true } }

// WithIssuer sets the issuer claim/discovery document field instead of
// defaulting to the httptest server's own URL.
func WithIssuer(iss string) IDPOption { return func(o *idpOptions) { o.issuer = iss } }

// WithKID sets the initial key ID instead of the default.
func WithKID(kid string) IDPOption { return func(o *idpOptions) { o.kid = kid } }

// TestIDP is a stand-in identity provider: an httptest server serving a
// JWKS document (and an OIDC discovery document pointing at it) for a
// generated keypair, plus Sign/SignWith to mint tokens against it.
type TestIDP struct {
	Server       *httptest.Server
	JWKSURL      string
	DiscoveryURL string
	Issuer       string
	KID          string

	mu       sync.Mutex
	kp       idpKeypair
	jwksJSON json.RawMessage
	rotation int

	jwksHits      atomic.Int64
	discoveryHits atomic.Int64
}

// NewTestIDP starts a TestIDP and registers tb.Cleanup to shut it down.
func NewTestIDP(tb testing.TB, opts ...IDPOption) *TestIDP {
	tb.Helper()

	o := idpOptions{kid: "test-key-1"}
	for _, opt := range opts {
		opt(&o)
	}

	idp := &TestIDP{KID: o.kid}
	idp.setKeypair(tb, newKeypair(tb, o.kid, o.es256, false))

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", idp.serveJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", idp.serveDiscovery)

	// Unstarted-then-Start avoids a data race between setting
	// idp.JWKSURL/Issuer below and the server's handler goroutines
	// reading them — nothing can reach the handlers until Start runs.
	idp.Server = httptest.NewUnstartedServer(mux)
	tb.Cleanup(idp.Server.Close)
	idp.Server.Start()

	idp.JWKSURL = idp.Server.URL + "/jwks.json"
	idp.DiscoveryURL = idp.Server.URL + "/.well-known/openid-configuration"
	if o.issuer != "" {
		idp.Issuer = o.issuer
	} else {
		idp.Issuer = idp.Server.URL
	}

	return idp
}

func (i *TestIDP) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	i.jwksHits.Add(1)
	i.mu.Lock()
	body := i.jwksJSON
	i.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (i *TestIDP) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	i.discoveryHits.Add(1)
	doc := map[string]string{
		"issuer":   i.Issuer,
		"jwks_uri": i.JWKSURL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// setKeypair builds a fresh JWKS document from kp and installs it as
// the current keypair/document, under the fixture's own mutex.
func (i *TestIDP) setKeypair(tb testing.TB, kp idpKeypair) {
	tb.Helper()

	store := jwkset.NewMemoryStorage()
	jwk, err := jwkset.NewJWKFromKey(kp.pub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: kp.kid, ALG: kp.alg, USE: jwkset.UseSig},
	})
	require.NoError(tb, err)
	require.NoError(tb, store.KeyWrite(context.Background(), jwk))
	raw, err := store.JSONPublic(context.Background())
	require.NoError(tb, err)

	i.mu.Lock()
	defer i.mu.Unlock()
	i.kp = kp
	i.jwksJSON = raw
}

// publicKey returns the current keypair's public key value (an
// *rsa.PublicKey or *ecdsa.PublicKey) — used by tests that need to
// construct an attack using the IDP's own published key material, e.g.
// the algorithm-confusion test in verify_test.go.
func (i *TestIDP) publicKey() any {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.kp.pub
}

// Sign mints a token signed with the IDP's current keypair and method.
func (i *TestIDP) Sign(tb testing.TB, claims jwt.Claims) string {
	tb.Helper()
	i.mu.Lock()
	kp := i.kp
	i.mu.Unlock()
	return i.sign(tb, kp.method, kp.priv, kp.kid, claims)
}

// SignWith mints a token with an arbitrary method/key — for negative
// tests (e.g. algorithm confusion: signing HS256 using the RSA public
// key's bytes as the HMAC secret) where the IDP's own keypair/method
// deliberately isn't what's used.
func (i *TestIDP) SignWith(tb testing.TB, method jwt.SigningMethod, key any, claims jwt.Claims) string {
	tb.Helper()
	i.mu.Lock()
	kid := i.kp.kid
	i.mu.Unlock()
	return i.sign(tb, method, key, kid, claims)
}

func (i *TestIDP) sign(tb testing.TB, method jwt.SigningMethod, key any, kid string, claims jwt.Claims) string {
	tb.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(tb, err)
	return signed
}

// Rotate swaps in a genuinely fresh keypair (same algorithm family as
// the current one, a new kid) and serves it from then on — for testing
// that a resolver picks up a real key change rather than caching the
// original keypair forever.
func (i *TestIDP) Rotate(tb testing.TB) {
	tb.Helper()
	i.mu.Lock()
	es256 := i.kp.alg == jwkset.AlgES256
	i.rotation++
	kid := fmt.Sprintf("%s-rotated-%d", i.KID, i.rotation)
	i.mu.Unlock()

	i.setKeypair(tb, newKeypair(tb, kid, es256, true))
}

// JWKSHits reports how many times the JWKS endpoint has been requested
// — used to assert a resolver caches rather than re-fetching per request.
func (i *TestIDP) JWKSHits() int { return int(i.jwksHits.Load()) }

// DiscoveryHits reports how many times the discovery endpoint has been
// requested.
func (i *TestIDP) DiscoveryHits() int { return int(i.discoveryHits.Load()) }
