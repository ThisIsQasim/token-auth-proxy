// Package authn verifies inbound credentials on requests arriving at
// the proxy, before they reach the reverse proxy handler.
//
// Three modes are implemented — HTTP Basic (username/password against
// bcrypt hashes), JWT bearer verification, and interactive SAML SP
// login (ACS route, SP-initiated redirects, session cookies) — and
// composed by NewMiddleware; see its doc comment for the precedence
// order between them.
package authn

import "github.com/ThisIsQasim/token-auth-proxy/internal/config"

// ConfigSource supplies the currently-live config, identically to
// proxy.ConfigSource. It's re-declared here rather than imported from
// internal/proxy so this package doesn't depend on proxy for a
// single-method interface it merely consumes — a value already typed
// as proxy.ConfigSource (e.g. *config.Watcher or *config.StaticSource)
// is assignable to this one without an adapter, since Go interface
// satisfaction is structural.
type ConfigSource interface {
	Current() *config.Config
}

// reason identifies why a request was rejected, for structured logging
// only — it is never included in the response body (see middleware.go's
// reject), so nothing here leaks verification internals to a caller.
type reason string

const (
	reasonNoCredential    reason = "no_credential" // #nosec G101 -- a log-field label, not a credential value
	reasonMalformedToken  reason = "malformed_token"
	reasonUnknownIssuer   reason = "unknown_issuer"
	reasonKeysUnavailable reason = "keys_unavailable"
	reasonExpired         reason = "expired"
	reasonNotYetValid     reason = "not_yet_valid"
	// reasonBadSignature also covers "algorithm not in the source's
	// allowlist" — golang-jwt v5 reports both as ErrTokenSignatureInvalid
	// (only the wrapped message text differs, and that text is not part
	// of its stable API), so there's no reliable sentinel to split them
	// on. See verify.go's classify.
	reasonBadSignature  reason = "bad_signature"
	reasonBadAudience   reason = "bad_audience"
	reasonBadIssuer     reason = "issuer_mismatch"
	reasonInvalidClaims reason = "invalid_claims"

	// reasonBadCredential covers a Basic credential that didn't verify.
	// It deliberately does NOT distinguish "no such user" from "wrong
	// password": /metrics is unauthenticated and always mounted, so a
	// split label would turn authn_rejections_total into a public
	// username-enumeration oracle — the exact thing Verify's
	// constant-time username match and padded compare exist to prevent.
	reasonBadCredential reason = "bad_credential" // #nosec G101 -- a log-field label, not a credential value
	// reasonMalformedCredential covers an Authorization header that
	// announced a scheme this proxy handles but couldn't be parsed
	// (bad base64, no colon after decoding).
	reasonMalformedCredential reason = "malformed_credential" // #nosec G101 -- a log-field label, not a credential value
	// reasonBasicSaturated indicates every bcrypt slot was busy for
	// longer than basicVerifyTimeout. Like reasonSAMLMetadataUnavailable
	// below, this is an operator/capacity problem rather than a caller
	// one, and gets a 503 rather than a 401.
	reasonBasicSaturated reason = "basic_saturated"

	// reasonSAMLMetadataUnavailable indicates SAMLRegistry.Provider
	// couldn't build/refresh a provider — the configured
	// idp_metadata_url is unreachable or malformed. Unlike every other
	// reason here, this is an operator problem, not a caller one; see
	// saml_middleware.go's rejectUnavailable.
	reasonSAMLMetadataUnavailable reason = "saml_metadata_unavailable"
)
