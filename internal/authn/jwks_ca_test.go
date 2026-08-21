package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// newTestCAPEM generates a fresh, self-signed CA certificate and returns
// it PEM-encoded, for use in a ca_cert field.
//
// ECDSA P-256 rather than RSA, and deliberately not cached the way the
// other keypair fixtures in this package are: the rotation and
// two-source cases below are only meaningful if every call yields a
// genuinely *different* certificate, and P-256 keygen is fast enough
// (sub-millisecond) that there's nothing to amortize. httptest's
// built-in TLS certificate can't serve here either — every
// httptest.NewTLSServer presents the same one.
func newTestCAPEM(tb testing.TB) string {
	tb.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(tb, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(tb, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func caJWTSource(name, jwksURL, caCert string) config.JWTSource {
	src := jwtSourceNamed(name, jwksURL)
	src.CACert = caCert
	return src
}

// rootCAsOf digs the trust roots out of a client built by
// newCACertClient, so a test can assert the pool really is the
// configured one rather than just that *some* client was made.
func rootCAsOf(tb testing.TB, client *http.Client) *x509.CertPool {
	tb.Helper()
	transport, ok := client.Transport.(*http.Transport)
	require.True(tb, ok, "expected an *http.Transport, got %T", client.Transport)
	require.NotNil(tb, transport.TLSClientConfig)
	return transport.TLSClientConfig.RootCAs
}

func TestRegistry_Keyfunc_NoCACertUsesTheSharedClient(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	_, err := r.Keyfunc(context.Background(), jwtSourceNamed("a", "https://a.example.com/jwks.json"))
	require.NoError(t, err)

	require.Len(t, calls, 1)
	assert.Same(t, r.client, calls[0].client, "a source with no ca_cert should share the registry's default client")
}

func TestRegistry_Keyfunc_CACertGetsItsOwnClient(t *testing.T) {
	caPEM := newTestCAPEM(t)

	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	_, err := r.Keyfunc(context.Background(), caJWTSource("a", "https://a.example.com/jwks.json", caPEM))
	require.NoError(t, err)

	require.Len(t, calls, 1)
	client := calls[0].client
	require.NotNil(t, client)
	assert.NotSame(t, r.client, client, "a ca_cert source needs its own client, not the shared one")
	assert.Equal(t, jwksHTTPTimeout, client.Timeout)

	want, err := config.ParseCACertPool(caPEM)
	require.NoError(t, err)
	assert.True(t, rootCAsOf(t, client).Equal(want), "the client's trust roots should be exactly the configured ca_cert")
}

func TestRegistry_Keyfunc_TwoCACertSourcesGetSeparateClients(t *testing.T) {
	caA := newTestCAPEM(t)
	caB := newTestCAPEM(t)
	require.NotEqual(t, caA, caB, "the fixture must produce distinguishable certificates")

	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	_, err := r.Keyfunc(context.Background(), caJWTSource("a", "https://a.example.com/jwks.json", caA))
	require.NoError(t, err)
	_, err = r.Keyfunc(context.Background(), caJWTSource("b", "https://b.example.com/jwks.json", caB))
	require.NoError(t, err)

	require.Len(t, calls, 2)
	assert.NotSame(t, calls[0].client, calls[1].client)

	wantA, err := config.ParseCACertPool(caA)
	require.NoError(t, err)
	wantB, err := config.ParseCACertPool(caB)
	require.NoError(t, err)
	assert.True(t, rootCAsOf(t, calls[0].client).Equal(wantA))
	assert.True(t, rootCAsOf(t, calls[1].client).Equal(wantB))
	assert.False(t, rootCAsOf(t, calls[0].client).Equal(wantB), "one source's pin must not leak into another's")
}

// A rotated CA is the whole point of putting CACert in the fingerprint:
// the PEM content changes with no other field moving, and the resolver
// must be rebuilt against the new roots rather than serving on with the
// old ones.
func TestRegistry_Keyfunc_CACertChangeRebuildsTheResolver(t *testing.T) {
	oldCA := newTestCAPEM(t)
	newCA := newTestCAPEM(t)

	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	src := caJWTSource("a", "https://a.example.com/jwks.json", oldCA)
	_, err := r.Keyfunc(context.Background(), src)
	require.NoError(t, err)
	// Same source again: cached, no rebuild.
	_, err = r.Keyfunc(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, calls, 1)

	rotated := caJWTSource("a", "https://a.example.com/jwks.json", newCA)
	assert.NotEqual(t, fingerprint(src), fingerprint(rotated))

	_, err = r.Keyfunc(context.Background(), rotated)
	require.NoError(t, err)
	require.Len(t, calls, 2, "rotating ca_cert should rebuild the resolver")

	want, err := config.ParseCACertPool(newCA)
	require.NoError(t, err)
	assert.True(t, rootCAsOf(t, calls[1].client).Equal(want), "the rebuilt resolver should use the new trust roots")
}

func TestRegistry_Keyfunc_InvalidCACertFailsAndIsNegativeCached(t *testing.T) {
	var mu sync.Mutex
	var calls []fakeKeyfuncCall
	r := newTestRegistry(t, newFakeNewKeyfunc(&calls, &mu, nil))

	now := time.Now()
	r.now = func() time.Time { return now }

	// Reachable only for a source that never went through
	// config.Validate, which rejects this at load time.
	src := caJWTSource("a", "https://a.example.com/jwks.json", "not a certificate")

	_, err := r.Keyfunc(context.Background(), src)
	require.Error(t, err)
	assert.ErrorContains(t, err, "ca_cert")
	assert.Empty(t, calls, "the resolver must not be built with unusable trust roots")

	// Inside the retry window the same error comes back without another
	// attempt, like every other build failure.
	_, err2 := r.Keyfunc(context.Background(), src)
	require.Error(t, err2)
	assert.Equal(t, err.Error(), err2.Error())
	assert.Empty(t, calls)
}
