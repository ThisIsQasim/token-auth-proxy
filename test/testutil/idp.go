package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
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
// two distinct identities. A test asserting something is rejected
// specifically because it was signed under a *different* key must call
// Rotate on one of the two IDPs first, or the "different" key won't
// actually be different.
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

func newIDPKeypair(tb testing.TB, kid string, es256, fresh bool) idpKeypair {
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
		if err != nil {
			tb.Fatalf("generate EC key: %v", err)
		}
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
	if err != nil {
		tb.Fatalf("generate RSA key: %v", err)
	}
	return idpKeypair{kid: kid, alg: jwkset.AlgRS256, method: jwt.SigningMethodRS256, priv: priv, pub: &priv.PublicKey}
}

// idpOptions configures NewTestIDP.
type idpOptions struct {
	es256  bool
	issuer string
	kid    string
	tls    bool
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

// WithTLS serves the JWKS and discovery endpoints over https, using
// httptest's own self-signed certificate — which no system trust store
// contains, so a client reaching it must be told to trust it. That's
// what makes it the fixture for a JWT source's ca_cert: see
// CACertPEM.
func WithTLS() IDPOption { return func(o *idpOptions) { o.tls = true } }

// TestIDP is a stand-in identity provider: an httptest server serving a
// JWKS document (and an OIDC discovery document pointing at it) for a
// generated keypair, plus Sign/SignWith to mint tokens against it. It's
// the non-test-file mirror of internal/authn's identical fixture — kept
// separate rather than shared, since _test.go files can't be imported
// across a module's package boundary, matching this file's existing
// non-test-file rationale (see testutil.go's package doc).
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
	idp.setKeypair(tb, newIDPKeypair(tb, o.kid, o.es256, false))

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", idp.serveJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", idp.serveDiscovery)

	// Unstarted-then-Start avoids a data race between setting
	// idp.JWKSURL/Issuer below and the server's handler goroutines
	// reading them — nothing can reach the handlers until Start runs.
	idp.Server = httptest.NewUnstartedServer(mux)
	tb.Cleanup(idp.Server.Close)
	if o.tls {
		idp.Server.StartTLS()
	} else {
		idp.Server.Start()
	}

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
	if err != nil {
		tb.Fatalf("build jwk: %v", err)
	}
	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		tb.Fatalf("write jwk: %v", err)
	}
	raw, err := store.JSONPublic(context.Background())
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.kp = kp
	i.jwksJSON = raw
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
// tests (e.g. algorithm confusion) where the IDP's own keypair/method
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
	if err != nil {
		tb.Fatalf("sign token: %v", err)
	}
	return signed
}

// Rotate swaps in a genuinely fresh keypair (same algorithm family as
// the current one, a new kid) and serves it from then on.
func (i *TestIDP) Rotate(tb testing.TB) {
	tb.Helper()
	i.mu.Lock()
	es256 := i.kp.alg == jwkset.AlgES256
	i.rotation++
	kid := fmt.Sprintf("%s-rotated-%d", i.KID, i.rotation)
	i.mu.Unlock()

	i.setKeypair(tb, newIDPKeypair(tb, kid, es256, true))
}

// CACertPEM returns the PEM-encoded certificate this IDP serves TLS
// with, ready to drop into a JWT source's ca_cert. httptest's
// certificate is self-signed, so it is its own root — pinning it is
// both what makes the fetch succeed and proof that it succeeded for the
// configured reason rather than by falling back to public trust.
//
// Only meaningful for an IDP started WithTLS; a plaintext one has no
// certificate and this fails the test rather than returning something
// unusable.
func (i *TestIDP) CACertPEM(tb testing.TB) string {
	tb.Helper()
	cert := i.Server.Certificate()
	if cert == nil {
		tb.Fatal("CACertPEM: this TestIDP was not started WithTLS, so it has no certificate")
		// Unreachable — tb.Fatal ends the goroutine — but staticcheck
		// can't see that, and without it flags the deref below.
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// JWKSHits reports how many times the JWKS endpoint has been requested
// — used to assert a resolver caches rather than re-fetching per request.
func (i *TestIDP) JWKSHits() int { return int(i.jwksHits.Load()) }

// DiscoveryHits reports how many times the discovery endpoint has been
// requested.
func (i *TestIDP) DiscoveryHits() int { return int(i.discoveryHits.Load()) }
