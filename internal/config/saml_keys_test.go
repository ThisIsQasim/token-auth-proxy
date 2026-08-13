package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSPPrivateKey_PKCS1(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))

	got, err := ParseSPPrivateKey(keyPEM)
	require.NoError(t, err)
	assert.True(t, priv.Equal(got))
}

func TestParseSPPrivateKey_PKCS8(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	got, err := ParseSPPrivateKey(keyPEM)
	require.NoError(t, err)
	assert.True(t, priv.Equal(got))
}

func TestParseSPPrivateKey_RejectsNonPEM(t *testing.T) {
	_, err := ParseSPPrivateKey("not a pem block at all")
	require.Error(t, err)
}

func TestParseSPPrivateKey_RejectsNonRSAKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err = ParseSPPrivateKey(keyPEM)
	require.Error(t, err)
	assert.ErrorContains(t, err, "RSA")
}

func TestParseSPCertificate(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	certPEM := testSPCertPEM(t, priv)

	cert, err := ParseSPCertificate(certPEM)
	require.NoError(t, err)
	assert.Equal(t, "test-sp", cert.Subject.CommonName)
}

func TestParseSPCertificate_RejectsNonPEM(t *testing.T) {
	_, err := ParseSPCertificate("not a pem block at all")
	require.Error(t, err)
}

func TestParseSPCertificate_RejectsMalformedDER(t *testing.T) {
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid der")}))
	_, err := ParseSPCertificate(badPEM)
	require.Error(t, err)
}
