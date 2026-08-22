package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
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

func TestParseCACertPool_Base64(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	certPEM := testSPCertPEM(t, priv)
	want, err := ParseSPCertificate(certPEM)
	require.NoError(t, err)
	wantPool := x509.NewCertPool()
	wantPool.AddCert(want)

	t.Run("single line, no armor stripped by hand", func(t *testing.T) {
		// The expected real-world case: cat ca.pem | base64 -w0 - the PEM
		// armor (BEGIN/END lines) travels through as part of the encoded
		// text, unmodified.
		encoded := base64.StdEncoding.EncodeToString([]byte(certPEM))
		pool, err := ParseCACertPool(encoded)
		require.NoError(t, err)
		assert.True(t, pool.Equal(wantPool))
	})

	t.Run("wrapped at 76 columns, like plain `base64` without -w0", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(certPEM))
		var wrapped strings.Builder
		for i := 0; i < len(encoded); i += 76 {
			end := min(i+76, len(encoded))
			wrapped.WriteString(encoded[i:end])
			wrapped.WriteByte('\n')
		}
		pool, err := ParseCACertPool(wrapped.String())
		require.NoError(t, err)
		assert.True(t, pool.Equal(wantPool))
	})

	t.Run("bundle", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		bundlePEM := certPEM + testSPCertPEM(t, other)
		encoded := base64.StdEncoding.EncodeToString([]byte(bundlePEM))

		pool, err := ParseCACertPool(encoded)
		require.NoError(t, err)

		want := x509.NewCertPool()
		require.True(t, want.AppendCertsFromPEM([]byte(bundlePEM)))
		assert.True(t, pool.Equal(want))
	})

	t.Run("invalid base64 falls back to the same not-found error", func(t *testing.T) {
		// "!!!!" has no PEM markers and isn't valid base64 either (not
		// alphabet, and not a multiple of 4 after that) - both attempts
		// fail, and the error should read as one clear message, not an
		// internal implementation detail about which attempt ran first.
		_, err := ParseCACertPool("!!!!")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM-encoded certificate found")
	})

	t.Run("valid base64 decoding to non-PEM garbage", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("just some bytes, not a certificate"))
		_, err := ParseCACertPool(encoded)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM-encoded certificate found")
	})

	t.Run("base64-decoded content that IS PEM but malformed reports the base64 path", func(t *testing.T) {
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
		encoded := base64.StdEncoding.EncodeToString([]byte(keyPEM))
		_, err := ParseCACertPool(encoded)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base64-decoded content")
		assert.Contains(t, err.Error(), `got "RSA PRIVATE KEY"`)
	})
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
		// pem.Decode reports "zero blocks, no error" identically for "no
		// PEM here at all" and "a BEGIN marker with no matching END" -
		// this must resolve to a PEM-shaped error (truncated/malformed),
		// not silently fall through to a "try base64" dead end whose
		// failure message points the operator at the wrong problem.
		{
			name:      "truncated PEM (BEGIN with no matching END)",
			pem:       "-----BEGIN CERTIFICATE-----\nMIIBxxsomepartialbase64datahere\n",
			errSubstr: "truncated or malformed",
		},
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
