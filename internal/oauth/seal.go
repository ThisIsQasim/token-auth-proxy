package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// The kinds of sealed value. A kind is bound into the seal as additional
// data, so a value sealed as one kind never opens as another: a refresh
// token cannot be presented as a login request, nor a login request as a
// finished login.
const (
	kindPending = "pending" // a login request that nobody has authenticated for yet
	kindDone    = "done"    // a login request after a successful login
	kindRefresh = "refresh"
)

var errBadToken = errors.New("invalid token")

// sealer seals values with AES-256-GCM. The first key seals; every key
// opens, so a key can be rotated out while what it sealed is still valid.
type sealer struct {
	aeads []cipher.AEAD
}

func newSealer(keys [][]byte) (*sealer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no sealing keys")
	}
	s := &sealer{}
	for i, k := range keys {
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("sealing key %d: %w", i, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("sealing key %d: %w", i, err)
		}
		s.aeads = append(s.aeads, aead)
	}
	return s, nil
}

// seal marshals v and seals it as kind, returning URL-safe text.
func (s *sealer) seal(kind string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	aead := s.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(kind))), nil
}

// open reverses seal for a value sealed as kind. Every failure is the same
// error: callers must not tell a client why a token was refused.
func (s *sealer) open(kind, token string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return errBadToken
	}
	for _, aead := range s.aeads {
		if len(raw) < aead.NonceSize() {
			continue
		}
		plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(kind))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(plain, v); err != nil {
			return errBadToken
		}
		return nil
	}
	return errBadToken
}
