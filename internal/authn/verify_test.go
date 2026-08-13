package authn

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// validJWTSource returns a JWTSource wired to idp's JWKS endpoint,
// already defaulted (algorithms/credentials filled in).
func validJWTSource(idp *TestIDP) config.JWTSource {
	j := config.JWTSource{
		Name:    "test-source",
		Issuer:  idp.Issuer,
		JWKSURL: idp.JWKSURL,
	}
	return j
}

// keyfuncFor is a minimal, no-caching jwt.Keyfunc that always resolves
// via idp's currently-served public key set — enough for verify_test.go
// and discovery_test.go, which are testing verify()/discovery in
// isolation, not the Registry's caching/lifecycle (that's jwks_test.go).
func keyfuncFor(t *testing.T, idp *TestIDP) jwt.Keyfunc {
	t.Helper()
	kf, err := keyfunc.NewDefaultCtx(t.Context(), []string{idp.JWKSURL})
	require.NoError(t, err)
	return kf.Keyfunc
}

func TestVerify_ValidToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []IDPOption
		algs []string
	}{
		{name: "RS256", opts: nil, algs: []string{"RS256"}},
		{name: "ES256", opts: []IDPOption{WithES256()}, algs: []string{"ES256"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := NewTestIDP(t, tc.opts...)
			src := validJWTSource(idp)
			src.Algorithms = tc.algs

			raw := idp.Sign(t, jwt.RegisteredClaims{
				Issuer:    idp.Issuer,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})

			claims, err := verify(raw, src, keyfuncFor(t, idp))
			require.NoError(t, err)
			assert.Equal(t, idp.Issuer, claims.Issuer)
		})
	}
}

// TestVerify_AlgorithmConfusion is the single highest-value test in
// this package: it proves the RFC 8725 §3.1 property JWTSource.Algorithms'
// doc comment has promised since the schema was designed — signing an
// HS256 token using the RSA public key's DER bytes as the HMAC secret
// (the classic algorithm-confusion attack: an attacker who can obtain
// the server's own public key can self-sign a token an RS256-only
// verifier would otherwise accept if it naively trusted the token's own
// alg header) must be rejected.
func TestVerify_AlgorithmConfusion(t *testing.T) {
	idp := NewTestIDP(t) // RS256
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}

	// The classic algorithm-confusion attack: an attacker who can obtain
	// the server's own RSA public key (public by definition — that's the
	// whole point of publishing a JWKS) self-signs an HS256 token using
	// those public key bytes as the HMAC secret. A verifier that naively
	// trusted the token's own alg header would treat the RSA public key
	// as a valid HMAC key and accept it. WithValidMethods must reject
	// this outright, before any key material is even consulted.
	der, err := x509.MarshalPKIXPublicKey(idp.publicKey())
	require.NoError(t, err)

	raw := idp.SignWith(t, jwt.SigningMethodHS256, der, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err = verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.Equal(t, reasonBadSignature, classify(err))
}

func TestVerify_AlgNoneRejected(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}

	raw := idp.SignWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.Equal(t, reasonBadSignature, classify(err))
}

func TestVerify_Expiry(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}
	src.ClockSkew = 30 * time.Second

	t.Run("expired well beyond leeway is rejected", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-2 * src.ClockSkew)),
		})
		_, err := verify(raw, src, keyfuncFor(t, idp))
		require.Error(t, err)
		assert.Equal(t, reasonExpired, classify(err))
	})

	t.Run("expired within leeway is accepted", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-src.ClockSkew / 2)),
		})
		_, err := verify(raw, src, keyfuncFor(t, idp))
		assert.NoError(t, err)
	})

	t.Run("missing exp is rejected (WithExpirationRequired)", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer})
		_, err := verify(raw, src, keyfuncFor(t, idp))
		require.Error(t, err)
	})
}

func TestVerify_NotBeforeInFuture(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}
	src.ClockSkew = 30 * time.Second

	raw := idp.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(2 * src.ClockSkew)),
	})

	_, err := verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.Equal(t, reasonNotYetValid, classify(err))
}

func TestVerify_WrongSigningKey(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}

	// A genuinely different keypair, deliberately kept under idp's same
	// kid — isolates "signature verification fails" (key lookup
	// succeeds, the bytes just don't match) from TestVerify_UnknownKID
	// (lookup itself fails). fresh=true bypasses the process-wide
	// shared-key cache so this key is provably not idp's own.
	wrongKey := newKeypair(t, idp.KID, false, true)

	raw := idp.SignWith(t, wrongKey.method, wrongKey.priv, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.Equal(t, reasonBadSignature, classify(err))
}

func TestVerify_UnknownKID(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}

	other := NewTestIDP(t, WithKID("some-other-kid"))
	raw := other.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.NotPanics(t, func() { classify(err) })
}

func TestVerify_Audience(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Algorithms = []string{"RS256"}

	t.Run("no restriction configured, no aud claim: accepted", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		_, err := verify(raw, src, keyfuncFor(t, idp))
		assert.NoError(t, err)
	})

	restricted := src
	restricted.Audiences = []string{"x"}

	t.Run("any-of: token aud contains one of several restricted values: accepted", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			Audience:  jwt.ClaimStrings{"y", "x"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		_, err := verify(raw, restricted, keyfuncFor(t, idp))
		assert.NoError(t, err)
	})

	t.Run("aud present but doesn't match: rejected", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			Audience:  jwt.ClaimStrings{"y"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		_, err := verify(raw, restricted, keyfuncFor(t, idp))
		require.Error(t, err)
		assert.Equal(t, reasonBadAudience, classify(err))
	})

	t.Run("audience restricted but token has no aud claim at all: rejected", func(t *testing.T) {
		raw := idp.Sign(t, jwt.RegisteredClaims{
			Issuer:    idp.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		_, err := verify(raw, restricted, keyfuncFor(t, idp))
		require.Error(t, err)
		// golang-jwt reports a missing-but-required claim as
		// ErrTokenRequiredClaimMissing (folded into reasonInvalidClaims
		// by classify), distinct from ErrTokenInvalidAudience which is
		// only for "present but doesn't match" — see verifyAudience in
		// golang-jwt's validator.go.
		assert.Equal(t, reasonInvalidClaims, classify(err))
	})
}

func TestVerify_IssuerMismatch(t *testing.T) {
	idp := NewTestIDP(t)
	src := validJWTSource(idp)
	src.Issuer = "https://configured-issuer.example.com" // deliberately different
	src.Algorithms = []string{"RS256"}

	raw := idp.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer, // token's actual issuer, != src.Issuer
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := verify(raw, src, keyfuncFor(t, idp))
	require.Error(t, err)
	assert.Equal(t, reasonBadIssuer, classify(err))
}

func TestUnverifiedIssuer(t *testing.T) {
	idp := NewTestIDP(t)
	raw := idp.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	iss, err := unverifiedIssuer(raw)
	require.NoError(t, err)
	assert.Equal(t, idp.Issuer, iss)
}

func TestUnverifiedIssuer_MalformedToken(t *testing.T) {
	_, err := unverifiedIssuer("not-a-jwt")
	require.Error(t, err)
}
