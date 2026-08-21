//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

// indentBlock indents every line of s for embedding under a YAML block
// scalar ("ca_cert: |"), where the content has to sit deeper than the
// key. PEM lines never contain tabs or trailing structure, so plain
// prefixing is enough.
func indentBlock(s string, spaces int) string {
	pad := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = pad + line
	}
	return strings.Join(lines, "\n")
}

// unrelatedCAPEM generates a self-signed CA that signed nothing in this
// test — the "operator pinned the wrong bundle" case. It has to be
// generated rather than borrowed from a second httptest server, because
// every httptest TLS server presents the same built-in certificate.
func unrelatedCAPEM(t *testing.T) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// tlsJWTConfig builds a full config whose single JWT source points at
// idp's https JWKS URL, with caCertYAML spliced in as the source's
// remaining lines (empty for the no-ca_cert case).
func tlsJWTConfig(backendURL string, idp *testutil.TestIDP, caCertYAML string) string {
	return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        jwks_url: %q
%s`, backendURL, idp.Issuer, idp.JWKSURL, caCertYAML)
}

// inlineCACert renders a ca_cert field holding PEM directly, the shape
// config.example.yaml documents.
func inlineCACert(pemStr string) string {
	return "        ca_cert: |\n" + indentBlock(pemStr, 10) + "\n"
}

func tlsIDPToken(t *testing.T, idp *testutil.TestIDP) string {
	t.Helper()
	return idp.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
}

func TestProxyJWT_CACertVerifiesHTTPSJWKS(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, inlineCACert(idp.CACertPEM(t))))

	proc := testutil.StartProxy(t, cfgPath)
	assertProxied(t, "http://"+proc.Addr+"/", bearerHeader(tlsIDPToken(t, idp)))
}

// The control for the test above: the JWKS is served under a
// certificate no public CA signed, so with nothing pinned the fetch
// fails and a perfectly valid token is still refused. Without this,
// the passing case above wouldn't distinguish "the pin worked" from
// "the certificate was trusted anyway."
func TestProxyJWT_HTTPSJWKSWithoutCACertIsRejected(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, ""))

	proc := testutil.StartProxy(t, cfgPath)
	assertRejected(t, "http://"+proc.Addr+"/", bearerHeader(tlsIDPToken(t, idp)))
}

// A pinned CA replaces the system trust store rather than extending it,
// so pinning the wrong bundle fails closed — it does not quietly fall
// back to whatever else might have verified the endpoint.
func TestProxyJWT_WrongCACertIsRejected(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, inlineCACert(unrelatedCAPEM(t))))

	proc := testutil.StartProxy(t, cfgPath)
	assertRejected(t, "http://"+proc.Addr+"/", bearerHeader(tlsIDPToken(t, idp)))
}

// The deployment shape the field is designed around: the CA arrives as
// a mounted file (a Kubernetes Secret, /var/run/secrets/...) and the
// config references it rather than inlining it.
func TestProxyJWT_CACertFromFileReference(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(idp.CACertPEM(t)), 0o600))

	cfgPath := filepath.Join(dir, "config.yaml")
	// A relative reference, resolved against the config file's own
	// directory.
	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, "        ca_cert: \"${file:ca.pem}\"\n"))

	proc := testutil.StartProxy(t, cfgPath)
	assertProxied(t, "http://"+proc.Addr+"/", bearerHeader(tlsIDPToken(t, idp)))
}

// The pin has to cover the discovery fetch too, not just the JWKS
// fetch: with oidc_discovery_url the proxy makes two https calls, and
// the first one is the one that would fail first.
func TestProxyJWT_CACertCoversOIDCDiscovery(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        oidc_discovery_url: %q
%s`, backend.URL, idp.Issuer, idp.DiscoveryURL, inlineCACert(idp.CACertPEM(t))))

	proc := testutil.StartProxy(t, cfgPath)
	assertProxied(t, "http://"+proc.Addr+"/", bearerHeader(tlsIDPToken(t, idp)))

	require.Positive(t, idp.DiscoveryHits(), "the discovery document should have been fetched over the pinned connection")
}

// Rotating the CA is a config change with no other field moving, so it
// only takes effect if ca_cert is part of the resolver fingerprint.
// Starting from a wrong pin also proves the rebuild isn't blocked by
// the failed build's negative cache, which is far longer than this
// test's timeout.
func TestProxyJWT_CACertRotationTakesEffectOnReload(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t, testutil.WithTLS())

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, inlineCACert(unrelatedCAPEM(t))))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr
	token := tlsIDPToken(t, idp)

	assertRejected(t, baseURL+"/", bearerHeader(token))

	testutil.WriteAtomic(t, cfgPath, tlsJWTConfig(backend.URL, idp, inlineCACert(idp.CACertPEM(t))))

	assertHeaderStatusEventually(t, baseURL+"/", bearerHeader(token), http.StatusOK, 10*time.Second)
	assertProxied(t, baseURL+"/", bearerHeader(token))
}
