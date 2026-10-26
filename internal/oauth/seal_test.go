package oauth

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestSealer_RoundTrip(t *testing.T) {
	s, err := newSealer([][]byte{testKey(t)})
	require.NoError(t, err)

	in := reqData{ClientID: "c", RedirectURI: "http://localhost/cb", Scopes: []string{"openid"}, Sub: "alice", Groups: []string{"a", "b"}, Exp: 42}
	tok, err := s.seal(kindDone, in)
	require.NoError(t, err)

	var out reqData
	require.NoError(t, s.open(kindDone, tok, &out))
	assert.Equal(t, in, out)

	other, err := s.seal(kindDone, in)
	require.NoError(t, err)
	assert.NotEqual(t, tok, other, "every seal uses a fresh nonce")
}

func TestSealer_KindsAreNotInterchangeable(t *testing.T) {
	s, err := newSealer([][]byte{testKey(t)})
	require.NoError(t, err)
	tok, err := s.seal(kindRefresh, refreshData{Sub: "alice", Exp: 1})
	require.NoError(t, err)

	for _, kind := range []string{kindPending, kindDone} {
		var d reqData
		assert.ErrorIs(t, s.open(kind, tok, &d), errBadToken, "a refresh token must not open as %s", kind)
	}
}

func TestSealer_RejectsGarbageAndTampering(t *testing.T) {
	s, err := newSealer([][]byte{testKey(t)})
	require.NoError(t, err)
	tok, err := s.seal(kindPending, reqData{ClientID: "c"})
	require.NoError(t, err)

	var d reqData
	for name, bad := range map[string]string{
		"empty":     "",
		"not b64":   "!!!",
		"short":     "AAAA",
		"truncated": tok[:len(tok)-4],
		"flipped":   tok[:10] + string(rune(tok[10]^1)) + tok[11:],
	} {
		assert.ErrorIs(t, s.open(kindPending, bad, &d), errBadToken, name)
	}
}

func TestSealer_Rotation(t *testing.T) {
	oldKey, newKey := testKey(t), testKey(t)

	old, err := newSealer([][]byte{oldKey})
	require.NoError(t, err)
	tok, err := old.seal(kindRefresh, refreshData{Sub: "alice", Exp: 1})
	require.NoError(t, err)

	rotated, err := newSealer([][]byte{newKey, oldKey})
	require.NoError(t, err)
	var d refreshData
	require.NoError(t, rotated.open(kindRefresh, tok, &d), "a rotated-out key still opens what it sealed")
	assert.Equal(t, "alice", d.Sub)

	fresh, err := rotated.seal(kindRefresh, refreshData{Sub: "bob", Exp: 1})
	require.NoError(t, err)
	onlyNew, err := newSealer([][]byte{newKey})
	require.NoError(t, err)
	require.NoError(t, onlyNew.open(kindRefresh, fresh, &d), "new values are sealed with the first key")
	assert.Equal(t, "bob", d.Sub)

	onlyOld, err := newSealer([][]byte{oldKey})
	require.NoError(t, err)
	assert.ErrorIs(t, onlyOld.open(kindRefresh, fresh, &d), errBadToken)
}

func TestNewSealer_Errors(t *testing.T) {
	_, err := newSealer(nil)
	assert.Error(t, err)
	_, err = newSealer([][]byte{[]byte("short")})
	assert.Error(t, err)
}
