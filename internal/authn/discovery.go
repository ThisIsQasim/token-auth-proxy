package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxDiscoveryBodyBytes caps how much of an OIDC discovery document
// this proxy will read, so a hostile or misbehaving discovery endpoint
// can't balloon memory.
const maxDiscoveryBodyBytes = 1 << 20 // 1 MiB

// discoveryDoc is the only part of an OpenID Provider Metadata document
// (OpenID Connect Discovery 1.0 §3) this proxy reads. Nothing else in
// the document is trusted or consulted — in particular, the advertised
// id_token_signing_alg_values_supported is deliberately ignored, since
// deriving trust parameters from the same remote document being
// verified is the algorithm-confusion foot-gun JWTSource.applyDefaults
// already warns about; JWTSource.Algorithms stays the sole authority.
type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// fetchJWKSURI fetches the OIDC discovery document at discoveryURL
// using client and returns its jwks_uri, after checking:
//   - the response is 200 and valid JSON;
//   - the document's issuer equals wantIssuer exactly — the one real
//     security property OIDC discovery adds over a bare jwks_url
//     (OpenID Connect Discovery 1.0 §4.3), cheap to check and worth
//     doing;
//   - jwks_uri is present and an absolute http(s) URL, the same rule
//     config.parseAbsoluteHTTPURL already enforces for every other URL
//     field in this schema (reimplemented locally in
//     validateAbsoluteHTTPURL — not worth exporting a one-caller
//     helper out of internal/config for this).
//
// Once resolved, the caller treats jwks_uri exactly like a directly
// configured jwks_url — one JWKS-resolution code path for both, see
// jwks.go.
func fetchJWKSURI(ctx context.Context, client *http.Client, discoveryURL, wantIssuer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G107 -- discoveryURL comes from validated operator config, not request input
	if err != nil {
		return "", fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery document: unexpected status %d", resp.StatusCode)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryBodyBytes)).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery document: %w", err)
	}

	if doc.Issuer != wantIssuer {
		return "", fmt.Errorf("discovery document issuer %q does not match configured issuer %q", doc.Issuer, wantIssuer)
	}

	if err := validateAbsoluteHTTPURL(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("discovery document jwks_uri: %w", err)
	}

	return doc.JWKSURI, nil
}

// validateAbsoluteHTTPURL checks raw is an absolute http(s) URL with a
// host — mirroring internal/config's parseAbsoluteHTTPURL rule.
func validateAbsoluteHTTPURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}
