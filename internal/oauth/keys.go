// Package oauth is the proxy's OAuth authorization server for MCP clients.
// It holds no state: login requests, authorization codes and refresh tokens
// are sealed blobs that carry what they need, and access tokens are ES256
// JWTs that the proxy and the backend verify against a published JWKS.
package oauth

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// signingKey is the key that signs: the first configured one.
type signingKey struct {
	kid string
	key *ecdsa.PrivateKey
}

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k signingKey) Key() any                                    { return k.key }
func (k signingKey) ID() string                                  { return k.kid }

// publicKey is one entry of the JWKS: every configured key, signing or not.
type publicKey struct {
	kid string
	key *ecdsa.PublicKey
}

func (k publicKey) ID() string                         { return k.kid }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return k.key }

// keyManager serves the signing key to the provider and the public keys to
// both the JWKS endpoint and the proxy's own verification of the tokens.
type keyManager struct {
	active signingKey
	public []publicKey
	byKID  map[string]*ecdsa.PublicKey
}

func newKeyManager(parsed []config.ParsedSigningKey) (*keyManager, error) {
	if len(parsed) == 0 {
		return nil, fmt.Errorf("no signing keys")
	}
	m := &keyManager{
		active: signingKey{kid: parsed[0].KID, key: parsed[0].Key},
		byKID:  make(map[string]*ecdsa.PublicKey, len(parsed)),
	}
	for _, k := range parsed {
		m.public = append(m.public, publicKey{kid: k.KID, key: &k.Key.PublicKey})
		m.byKID[k.KID] = &k.Key.PublicKey
	}
	return m, nil
}

func (m *keyManager) signing() op.SigningKey { return m.active }

func (m *keyManager) keySet() []op.Key {
	out := make([]op.Key, len(m.public))
	for i, k := range m.public {
		out[i] = k
	}
	return out
}

// keyfunc resolves the verification key of a token by its kid header, for
// the JWT leg's verification of the tokens this server issued.
func (m *keyManager) keyfunc() jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := m.byKID[kid]
		if !ok {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		return key, nil
	}
}
