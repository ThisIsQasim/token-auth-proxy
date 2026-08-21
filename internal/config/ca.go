package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCACertPool parses pemStr as one or more concatenated PEM-encoded
// X.509 certificates and returns a pool containing exactly those.
//
// The pool is deliberately never seeded from x509.SystemCertPool: a
// configured CA *replaces* the system trust store for the endpoint it's
// attached to (curl --cacert semantics), it doesn't extend it. Adding
// to the system pool would mean a typo'd or truncated ca_cert silently
// degrades to plain public trust — the endpoint keeps working, verified
// by a CA the operator never named — which is precisely the failure this
// field exists to prevent. Replacing makes that case a loud handshake
// error instead.
//
// Every block must be a parseable CERTIFICATE, and at least one must be
// present. x509.CertPool.AppendCertsFromPEM alone would report success
// as long as *any* single block parsed, silently dropping the rest — so
// a bundle with one good root and one corrupt intermediate would load
// clean here and fail later, mid-handshake, with a chain error naming
// neither. Parsing block by block turns that into a config-load error
// naming the block.
//
// Exported so internal/authn can build the same pool at resolver-build
// time without duplicating the parsing, matching ParseSPCertificate's
// rationale.
func ParseCACertPool(pemStr string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := []byte(pemStr)
	n := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		n++
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("block %d: expected a CERTIFICATE block, got %q", n, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", n, err)
		}
		// AddCert, not AppendCertsFromPEM: the certificate is already
		// parsed, and this way the pool holds exactly the blocks that
		// were counted above.
		pool.AddCert(cert)
	}

	if n == 0 {
		return nil, fmt.Errorf("no PEM-encoded certificate found")
	}
	return pool, nil
}
