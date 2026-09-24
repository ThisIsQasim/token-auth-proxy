package authn

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// unverifiedIssuer returns raw's iss claim without verifying anything
// about the token — no signature check, no claims validation. This is
// the only value ever read from an unverified token, and it exists
// solely to select which configured source's keys and policy to verify
// under; whether it was truthful is settled by jwt.WithIssuer inside
// the real, signature-checked parse in verify.
func unverifiedIssuer(raw string) (string, error) {
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &claims); err != nil {
		return "", err
	}
	return claims.Issuer, nil
}

// parserFor builds the verification policy for src:
//   - the algorithm allowlist (RFC 8725 §3.1 — the token's own alg
//     header is never consulted to choose which algorithms are
//     trusted, only checked against this pre-configured list);
//   - the clock-skew leeway applied to exp/nbf;
//   - the required issuer, which doubles as the post-routing recheck
//     that the now-verified iss still equals what was used to select
//     src in the first place;
//   - the any-of audience set, only when src restricts audiences —
//     JWTSource.Audiences is documented as "empty = unrestricted", and
//     jwt.WithAudience (v5.3.0+) is variadic any-of matching, so this
//     is a direct translation with no hand-rolled intersection logic.
//
// Expiration is unconditionally required: golang-jwt does not require
// an exp claim by default, so an eternal bearer token would otherwise
// verify forever — a real liability for a credential accepted by a
// proxy. This matches JWTSource.applyDefaults' existing fail-closed
// philosophy (a missing default rejects, rather than silently
// downgrading trust).
func parserFor(src config.JWTSource) *jwt.Parser {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(src.Algorithms),
		jwt.WithLeeway(src.ClockSkew),
		jwt.WithIssuer(src.Issuer),
		jwt.WithExpirationRequired(),
	}
	if len(src.Audiences) > 0 {
		opts = append(opts, jwt.WithAudience(src.Audiences...))
	}
	return jwt.NewParser(opts...)
}

// verify parses and fully validates raw under src's policy, resolving
// signing keys via kf. Every claim is returned, not just the registered
// ones, so ACL rules can match on custom claims.
func verify(raw string, src config.JWTSource, kf jwt.Keyfunc) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if _, err := parserFor(src).ParseWithClaims(raw, claims, kf); err != nil {
		return nil, err
	}
	return claims, nil
}

// classify maps a golang-jwt verification error to the reason logged
// server-side (never returned to the caller — see middleware.go's
// reject). golang-jwt v5 joins multiple validation failures into one
// error, so errors.Is (not ==) is required; check order determines
// which single reason is reported when more than one applies.
func classify(err error) reason {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return reasonExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return reasonNotYetValid
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return reasonBadAudience
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return reasonBadIssuer
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// Also covers "algorithm not in src.Algorithms" — see
		// reasonBadSignature's doc comment in authn.go.
		return reasonBadSignature
	case errors.Is(err, jwt.ErrTokenMalformed), errors.Is(err, jwt.ErrTokenUnverifiable):
		return reasonMalformedToken
	default:
		return reasonInvalidClaims
	}
}
