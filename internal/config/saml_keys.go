package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseSPPrivateKey parses pemStr as a PEM-encoded RSA private key,
// accepting either PKCS#1 ("RSA PRIVATE KEY", openssl's default) or
// PKCS#8 ("PRIVATE KEY") blocks — the two encodings most tooling
// produces. Exported so internal/authn can re-parse the same env var
// value at provider-build time (defense in depth, matching
// SessionSigningKeyEnv's "re-check, don't trust config-load-time
// validation forever" rationale) without duplicating the parsing logic.
//
// RSA only, deliberately: this proxy's SAML stack
// (github.com/crewjam/saml/xmlenc) only ever implements RSA-OAEP key
// transport for XML-Encryption, so any other key type would fail
// confusingly deep inside a decrypt call during a real login rather
// than here, once, at config-validate time.
func ParseSPPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("not a PEM-encoded private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("must be an RSA private key, got %T", key)
	}
	return rsaKey, nil
}

// ParseSPCertificate parses pemStr as a single PEM-encoded X.509
// certificate. Exported for the same defense-in-depth reason as
// ParseSPPrivateKey.
func ParseSPCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("not a PEM-encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}
