package authn

import (
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAssertion(attrs map[string][]string, sessionIndex string) *saml.Assertion {
	var attrStmts []saml.AttributeStatement
	if len(attrs) > 0 {
		var attributes []saml.Attribute
		for name, values := range attrs {
			var avs []saml.AttributeValue
			for _, v := range values {
				avs = append(avs, saml.AttributeValue{Value: v})
			}
			attributes = append(attributes, saml.Attribute{FriendlyName: name, Values: avs})
		}
		attrStmts = []saml.AttributeStatement{{Attributes: attributes}}
	}
	var authnStmts []saml.AuthnStatement
	if sessionIndex != "" {
		authnStmts = []saml.AuthnStatement{{SessionIndex: sessionIndex}}
	}
	return &saml.Assertion{
		Subject:             &saml.Subject{NameID: &saml.NameID{Value: "user@example.com"}},
		AttributeStatements: attrStmts,
		AuthnStatements:     authnStmts,
	}
}

func testSessionCodec(now func() time.Time) samlSessionCodec {
	return samlSessionCodec{
		secret:   []byte(validSAMLSessionKeyForTest),
		audience: "https://proxy.example.com/saml/metadata",
		issuer:   "https://proxy.example.com/saml/metadata",
		maxAge:   time.Hour,
		now:      now,
	}
}

const validSAMLSessionKeyForTest = "01234567890123456789012345678901"

func TestSAMLSessionCodec_RoundTrip(t *testing.T) {
	codec := testSessionCodec(time.Now)
	assertion := testAssertion(map[string][]string{"email": {"user@example.com"}}, "session-idx-1")

	session, err := codec.New(assertion)
	require.NoError(t, err)

	encoded, err := codec.Encode(session)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	decoded, err := codec.Decode(encoded)
	require.NoError(t, err)

	claims, ok := decoded.(samlSessionClaims)
	require.True(t, ok)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, []string{"user@example.com"}, claims.Attributes["email"])
	assert.Equal(t, []string{"session-idx-1"}, claims.Attributes[samlSessionIndexAttr])
	assert.True(t, claims.SAMLSession)
}

func TestSAMLSessionCodec_Expired(t *testing.T) {
	now := time.Now()
	codec := testSessionCodec(func() time.Time { return now })
	codec.maxAge = time.Minute

	session, err := codec.New(testAssertion(nil, ""))
	require.NoError(t, err)
	encoded, err := codec.Encode(session)
	require.NoError(t, err)

	// Advance the clock well past maxAge.
	future := testSessionCodec(func() time.Time { return now.Add(2 * time.Hour) })
	_, err = future.Decode(encoded)
	require.Error(t, err)
}

func TestSAMLSessionCodec_Tampered(t *testing.T) {
	codec := testSessionCodec(time.Now)
	session, err := codec.New(testAssertion(nil, ""))
	require.NoError(t, err)
	encoded, err := codec.Encode(session)
	require.NoError(t, err)

	// Tamper with the *first* character of the signature, deliberately
	// not the last. A 32-byte HMAC is 256 bits, so its final base64url
	// character carries only four significant bits — the remaining two
	// are don't-care, and Go's (non-strict) decoder ignores them. Four
	// different final characters therefore decode to the identical
	// signature, so editing the last character leaves the token valid
	// often enough to make this test flaky. Every bit of the first
	// character is significant, so changing it always changes the
	// signature.
	dot := strings.LastIndexByte(encoded, '.')
	require.Positive(t, dot, "expected a JWT-shaped session token")
	sig := []byte(encoded[dot+1:])
	require.NotEmpty(t, sig)
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}

	_, err = codec.Decode(encoded[:dot+1] + string(sig))
	require.Error(t, err)
}

func TestSAMLSessionCodec_WrongSecret(t *testing.T) {
	codec := testSessionCodec(time.Now)
	session, err := codec.New(testAssertion(nil, ""))
	require.NoError(t, err)
	encoded, err := codec.Encode(session)
	require.NoError(t, err)

	other := codec
	other.secret = []byte("98765432109876543210987654321098")
	_, err = other.Decode(encoded)
	require.Error(t, err)
}

func TestSAMLSessionCodec_AlgorithmMismatchRejected(t *testing.T) {
	codec := testSessionCodec(time.Now)
	claims := samlSessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{codec.audience},
			Issuer:    codec.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		SAMLSession: true,
	}
	// alg: none must be rejected even though the claims are otherwise valid.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = codec.Decode(signed)
	require.Error(t, err)
}

func TestSAMLSessionCodec_AudienceIssuerMismatch(t *testing.T) {
	codec := testSessionCodec(time.Now)
	session, err := codec.New(testAssertion(nil, ""))
	require.NoError(t, err)
	encoded, err := codec.Encode(session)
	require.NoError(t, err)

	t.Run("wrong audience", func(t *testing.T) {
		other := codec
		other.audience = "https://different-sp.example.com"
		_, err := other.Decode(encoded)
		require.Error(t, err)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		other := codec
		other.issuer = "https://different-sp.example.com"
		_, err := other.Decode(encoded)
		require.Error(t, err)
	})
}

func TestSAMLSessionCodec_MissingMarkerClaimRejected(t *testing.T) {
	codec := testSessionCodec(time.Now)
	claims := samlSessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{codec.audience},
			Issuer:    codec.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		SAMLSession: false, // deliberately not marked as a session
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(codec.secret)
	require.NoError(t, err)

	_, err = codec.Decode(signed)
	require.Error(t, err)
}

// --- tracked-request codec ---

func testTrackedRequestCodec(now func() time.Time) samlTrackedRequestCodec {
	return samlTrackedRequestCodec{
		secret:   []byte(validSAMLSessionKeyForTest),
		audience: "https://proxy.example.com/saml/metadata",
		issuer:   "https://proxy.example.com/saml/metadata",
		maxAge:   saml.MaxIssueDelay,
		now:      now,
	}
}

func TestSAMLTrackedRequestCodec_RoundTrip(t *testing.T) {
	codec := testTrackedRequestCodec(time.Now)
	req := samlsp.TrackedRequest{Index: "idx-1", SAMLRequestID: "req-id-1", URI: "/protected"}

	encoded, err := codec.Encode(req)
	require.NoError(t, err)

	decoded, err := codec.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, "idx-1", decoded.Index)
	assert.Equal(t, "req-id-1", decoded.SAMLRequestID)
	assert.Equal(t, "/protected", decoded.URI)
}

func TestSAMLTrackedRequestCodec_Expired(t *testing.T) {
	now := time.Now()
	codec := testTrackedRequestCodec(func() time.Time { return now })
	codec.maxAge = time.Minute
	encoded, err := codec.Encode(samlsp.TrackedRequest{Index: "idx-1", SAMLRequestID: "req-id-1", URI: "/x"})
	require.NoError(t, err)

	future := testTrackedRequestCodec(func() time.Time { return now.Add(2 * time.Hour) })
	future.maxAge = time.Minute
	_, err = future.Decode(encoded)
	require.Error(t, err)
}

func TestSAMLTrackedRequestCodec_WrongSecretRejected(t *testing.T) {
	codec := testTrackedRequestCodec(time.Now)
	encoded, err := codec.Encode(samlsp.TrackedRequest{Index: "idx-1", SAMLRequestID: "req-id-1", URI: "/x"})
	require.NoError(t, err)

	other := codec
	other.secret = []byte("98765432109876543210987654321098")
	_, err = other.Decode(encoded)
	require.Error(t, err)
}

func TestSAMLTrackedRequestCodec_MissingMarkerClaimRejected(t *testing.T) {
	codec := testTrackedRequestCodec(time.Now)
	// A session token (wrong marker claim) must not decode as a tracked
	// request, even though both use the same secret/algorithm.
	sc := testSessionCodec(time.Now)
	sc.secret = codec.secret
	session, err := sc.New(testAssertion(nil, ""))
	require.NoError(t, err)
	encoded, err := sc.Encode(session)
	require.NoError(t, err)

	_, err = codec.Decode(encoded)
	require.Error(t, err)
}
