package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// ParseCACertPool parses raw as one or more concatenated PEM-encoded
// X.509 certificates, or — if it contains no PEM markers at all — as
// that same PEM content base64-encoded instead, and returns a pool
// containing exactly those certificates.
//
// Base64 is accepted for exactly one reason: it has no embedded
// newlines, so it's the friendlier form to paste as a single JSON
// string — a --inbound-auth-*-json flag or its TAP_*_JSON env var,
// which (unlike the YAML config file) has no interpolation and no
// block-scalar syntax to carry raw PEM's newlines for you. Whitespace
// (including embedded newlines) is stripped before decoding, so
// conventionally-wrapped base64 output — most `base64`/`openssl base64`
// invocations wrap at 64-76 columns — works unmodified too.
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
func ParseCACertPool(raw string) (*x509.CertPool, error) {
	pool, n, err := decodePEMCertBlocks([]byte(raw))
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return pool, nil
	}

	// pem.Decode returns this same "zero blocks, no error" result both
	// for raw containing no PEM markers at all, and for raw containing
	// a "-----BEGIN"-started block that's truncated or otherwise
	// malformed (no matching "-----END" line) - it can't tell those two
	// apart. Only the first is a real base64 candidate; the second was
	// clearly meant as PEM, so give it a PEM-shaped error naming the
	// actual problem instead of routing it into a base64 attempt that
	// can only ever fail (raw still contains literal "-----BEGIN...-----"
	// text, which isn't valid base64) and reports a misleading "try
	// base64" message for what's really a malformed-PEM problem.
	if strings.Contains(raw, "-----BEGIN") {
		return nil, errors.New("no PEM-encoded certificate found: a \"-----BEGIN\" marker is present but the block looks truncated or malformed (no matching \"-----END\" line?)")
	}

	// No PEM markers anywhere in raw - it isn't PEM at all, or it's PEM
	// with the "-----BEGIN/END-----" armor stripped off, which is
	// exactly what base64-encoding the whole thing looks like. Try
	// that next, rather than failing on the first form tried.
	stripped := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	decoded, decodeErr := base64.StdEncoding.DecodeString(stripped)
	if decodeErr != nil {
		return nil, errors.New("no PEM-encoded certificate found (and it's not valid base64 either)")
	}
	pool, n, err = decodePEMCertBlocks(decoded)
	if err != nil {
		return nil, fmt.Errorf("base64-decoded content: %w", err)
	}
	if n == 0 {
		return nil, errors.New("no PEM-encoded certificate found")
	}
	return pool, nil
}

// decodePEMCertBlocks parses every PEM block in raw as an X.509
// certificate, adding each to a fresh pool. n is how many blocks were
// found — 0 means raw contained no PEM data at all, which is not
// itself an error here; it's ParseCACertPool's signal to try raw as
// base64 next. A block that *is* found but isn't a well-formed
// CERTIFICATE is a real error, returned immediately: raw was clearly
// meant as PEM, so this shouldn't be swallowed into a base64 retry.
func decodePEMCertBlocks(raw []byte) (pool *x509.CertPool, n int, err error) {
	pool = x509.NewCertPool()
	rest := raw

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		n++
		if block.Type != "CERTIFICATE" {
			return nil, 0, fmt.Errorf("block %d: expected a CERTIFICATE block, got %q", n, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("block %d: %w", n, err)
		}
		// AddCert, not AppendCertsFromPEM: the certificate is already
		// parsed, and this way the pool holds exactly the blocks that
		// were counted above.
		pool.AddCert(cert)
	}

	return pool, n, nil
}
