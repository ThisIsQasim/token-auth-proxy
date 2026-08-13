// Package authn verifies inbound credentials on requests arriving at
// the proxy, before they reach the reverse proxy handler.
//
// Both JWT bearer verification and interactive SAML SP login (ACS
// route, SP-initiated redirects, session cookies) are implemented and
// composed by NewMiddleware — see its doc comment for the precedence
// order between the two.
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

	// reasonSAMLMetadataUnavailable indicates SAMLRegistry.Provider
	// couldn't build/refresh a provider — the configured
	// idp_metadata_url is unreachable or malformed. Unlike every other
	// reason here, this is an operator problem, not a caller one; see
	// saml_middleware.go's rejectUnavailable.
	reasonSAMLMetadataUnavailable reason = "saml_metadata_unavailable"
)
