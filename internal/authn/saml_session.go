package authn

import (
	"errors"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/golang-jwt/jwt/v5"
)

// samlSessionAlg is the only signing algorithm accepted for both the
// session cookie and the short-lived request-tracking cookie.
// Symmetric deliberately: SessionSigningKeyEnv names an env var holding
// a shared secret, and unlike a JWT source there is no remote key
// material in play — see allowedAlgorithms' "no HS*" rationale in
// internal/config/auth.go for why JWT sources and this are opposite.
const samlSessionAlg = "HS256"

// samlSessionIndexAttr is the attribute key AuthnStatements' SessionIndex
// is stored under, matching samlsp's own JWTSessionCodec convention
// (claimNameSessionIndex) so the shape is familiar to anyone who's used
// crewjam/saml's default session codec.
const samlSessionIndexAttr = "SessionIndex"

// samlSessionClaims is the JWT claims shape for a SAML session cookie —
// modeled on samlsp.JWTSessionClaims (samlsp/session_jwt.go) but with
// golang-jwt/jwt/v5 RegisteredClaims (matching verify.go, the JWT
// pass's own codec) and a symmetric signature (see samlSessionCodec).
type samlSessionClaims struct {
	jwt.RegisteredClaims
	Attributes  samlsp.Attributes `json:"attr"`
	SAMLSession bool              `json:"saml-session"`
}

var (
	_ samlsp.Session               = samlSessionClaims{}
	_ samlsp.SessionWithAttributes = samlSessionClaims{}
)

// GetAttributes implements samlsp.SessionWithAttributes.
func (c samlSessionClaims) GetAttributes() samlsp.Attributes { return c.Attributes }

// samlSessionCodec implements samlsp.SessionCodec using HS256 and the
// secret named by SAMLSource.SessionSigningKeyEnv, rather than
// samlsp's own default codec (which signs with an asymmetric SP
// keypair this proxy deliberately doesn't have — see saml.go's
// buildSAMLProvider doc comment for why).
type samlSessionCodec struct {
	secret   []byte
	audience string        // SAMLSource.SPEntityID
	issuer   string        // SAMLSource.SPEntityID
	maxAge   time.Duration // SAMLSource.SessionDuration
	now      func() time.Time
}

var _ samlsp.SessionCodec = samlSessionCodec{}

// New creates a Session from a validated SAML assertion — modeled on
// samlsp.JWTSessionCodec.New field-for-field: subject from the NameID,
// attributes from AttributeStatements (keyed by FriendlyName, falling
// back to Name), plus AuthnStatements' SessionIndex appended under
// samlSessionIndexAttr.
func (c samlSessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	now := c.now()
	claims := samlSessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{c.audience},
			Issuer:    c.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(c.maxAge)),
		},
		SAMLSession: true,
		Attributes:  samlsp.Attributes{},
	}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		claims.Subject = assertion.Subject.NameID.Value
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := attr.FriendlyName
			if name == "" {
				name = attr.Name
			}
			for _, v := range attr.Values {
				claims.Attributes[name] = append(claims.Attributes[name], v.Value)
			}
		}
	}
	for _, stmt := range assertion.AuthnStatements {
		claims.Attributes[samlSessionIndexAttr] = append(claims.Attributes[samlSessionIndexAttr], stmt.SessionIndex)
	}

	return claims, nil
}

// Encode returns a serialized version of the Session. s must be a
// samlSessionClaims — matching SessionCodec's documented contract that
// implementations may panic on the wrong concrete type, since New is
// always what produces the value passed here.
func (c samlSessionCodec) Encode(s samlsp.Session) (string, error) {
	claims := s.(samlSessionClaims) //nolint:forcetypeassert // documented SessionCodec contract, see doc comment
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(c.secret)
}

// Decode parses and fully validates a session cookie value. Any
// failure — expired, wrong secret, wrong algorithm, wrong aud/iss,
// missing the SAMLSession marker — returns an error, which
// samlsp.CookieSessionProvider.GetSession maps to samlsp.ErrNoSession,
// exactly the "invalid session -> re-authenticate" behavior wanted.
func (c samlSessionCodec) Decode(signed string) (samlsp.Session, error) {
	var claims samlSessionClaims
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{samlSessionAlg}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(c.now),
	).ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) {
		return c.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !claims.SAMLSession {
		return nil, errors.New("saml: token is not a session")
	}
	return claims, nil
}

// samlTrackedRequestClaims is the JWT claims shape for the short-lived
// "saml_"-prefixed cookie that survives the SP-initiated redirect round
// trip, carrying the original URL and the expected SAML request ID.
// Modeled on samlsp.JWTTrackedRequestClaims (samlsp/request_tracker_jwt.go)
// but symmetric — see samlSessionCodec's doc comment for why.
type samlTrackedRequestClaims struct {
	jwt.RegisteredClaims
	samlsp.TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// samlTrackedRequestCodec implements samlsp.TrackedRequestCodec using
// HS256 and the same secret samlSessionCodec uses. Sharing one secret
// across both is fine — both are derived from SessionSigningKeyEnv (no
// separate persisted identity for the tracker), and each is namespaced
// by its own marker claim (SAMLSession vs SAMLAuthnRequest), so a
// tracked-request token can never be replayed as a session or vice versa.
type samlTrackedRequestCodec struct {
	secret           []byte
	audience, issuer string
	maxAge           time.Duration // saml.MaxIssueDelay
	now              func() time.Time
}

var _ samlsp.TrackedRequestCodec = samlTrackedRequestCodec{}

// Encode returns an encoded string representing the TrackedRequest.
func (c samlTrackedRequestCodec) Encode(v samlsp.TrackedRequest) (string, error) {
	now := c.now()
	claims := samlTrackedRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{c.audience},
			Issuer:    c.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(c.maxAge)),
			Subject:   v.Index,
		},
		TrackedRequest:   v,
		SAMLAuthnRequest: true,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(c.secret)
}

// Decode returns a TrackedRequest from an encoded string, or an error
// for any of the same reasons samlSessionCodec.Decode can fail.
func (c samlTrackedRequestCodec) Decode(signed string) (*samlsp.TrackedRequest, error) {
	var claims samlTrackedRequestClaims
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{samlSessionAlg}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(c.now),
	).ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) {
		return c.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !claims.SAMLAuthnRequest {
		return nil, errors.New("saml: token is not a tracked request")
	}
	// TrackedRequest.Index is tagged `json:"-"` (deliberately excluded
	// from the encoded body, matching samlsp's own reference codec) so
	// it's recovered from the standard sub claim instead.
	claims.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
