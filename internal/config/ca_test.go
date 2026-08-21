package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCACertPool_SingleCertificate(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	certPEM := testSPCertPEM(t, priv)

	pool, err := ParseCACertPool(certPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)

	cert, err := ParseSPCertificate(certPEM)
	require.NoError(t, err)
	want := x509.NewCertPool()
	want.AddCert(cert)
	assert.True(t, pool.Equal(want), "pool should contain exactly the one configured certificate")
}

func TestParseCACertPool_Bundle(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Two concatenated certs, the shape of a real CA bundle (root plus
	// intermediate).
	bundle := testSPCertPEM(t, priv) + testSPCertPEM(t, other)

	pool, err := ParseCACertPool(bundle)
	require.NoError(t, err)

	want := x509.NewCertPool()
	require.True(t, want.AppendCertsFromPEM([]byte(bundle)))
	assert.True(t, pool.Equal(want), "pool should contain both certificates in the bundle")
}

func TestParseCACertPool_Rejects(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	goodPEM := testSPCertPEM(t, priv)

	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	malformedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid der")}))

	tests := []struct {
		name      string
		pem       string
		errSubstr string
	}{
		{name: "empty", pem: "", errSubstr: "no PEM-encoded certificate found"},
		{name: "not PEM at all", pem: "not a pem block", errSubstr: "no PEM-encoded certificate found"},
		{name: "private key block", pem: keyPEM, errSubstr: `got "RSA PRIVATE KEY"`},
		{name: "malformed DER", pem: malformedPEM, errSubstr: "block 1"},
		// The case AppendCertsFromPEM would silently accept: a valid
		// root followed by a corrupt intermediate. Loading it clean here
		// would move the failure to mid-handshake, where the chain error
		// names neither block.
		{name: "good cert then corrupt cert", pem: goodPEM + malformedPEM, errSubstr: "block 2"},
		{name: "good cert then private key", pem: goodPEM + keyPEM, errSubstr: "block 2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCACertPool(tc.pem)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errSubstr)
		})
	}
}
