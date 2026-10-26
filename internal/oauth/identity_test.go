package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

var defaultNames = config.TokenClaims{Subject: "sub", Email: "email", Groups: "groups"}

func TestIdentity_Extract_JWTClaims(t *testing.T) {
	id := Identity{Mode: "jwt", Claims: map[string]any{
		"sub": "alice", "email": "alice@example.com", "groups": []any{"os-mcp-readers", 7, "", "ops"},
	}}
	sub, email, groups, err := id.extract(defaultNames)
	require.NoError(t, err)
	assert.Equal(t, "alice", sub)
	assert.Equal(t, "alice@example.com", email)
	assert.Equal(t, []string{"os-mcp-readers", "ops"}, groups, "non-strings and blanks are dropped")
}

func TestIdentity_Extract_SAMLAttributes(t *testing.T) {
	id := Identity{Mode: "saml", Claims: map[string]any{
		"sub":   "name-id-1",
		"Mail":  []string{"alice@example.com", "other@example.com"},
		"Roles": []string{"os-mcp-readers", "ops"},
	}}
	sub, email, groups, err := id.extract(config.TokenClaims{Subject: "sub", Email: "Mail", Groups: "Roles"})
	require.NoError(t, err)
	assert.Equal(t, "name-id-1", sub)
	assert.Equal(t, "alice@example.com", email, "the first of a multi-valued attribute")
	assert.Equal(t, []string{"os-mcp-readers", "ops"}, groups)
}

func TestIdentity_Extract_Basic(t *testing.T) {
	sub, email, groups, err := Identity{Mode: "basic", Username: "alice"}.extract(defaultNames)
	require.NoError(t, err)
	assert.Equal(t, "alice", sub)
	assert.Empty(t, email)
	assert.Empty(t, groups)
}

func TestIdentity_Extract_Errors(t *testing.T) {
	_, _, _, err := Identity{Mode: "jwt", Claims: map[string]any{"email": "a@b"}}.extract(defaultNames)
	assert.ErrorContains(t, err, "no \"sub\" claim")

	_, _, _, err = Identity{Mode: "jwt", Claims: map[string]any{"sub": 42}}.extract(defaultNames)
	assert.Error(t, err, "a non-string subject is no subject")
}

func TestStringList(t *testing.T) {
	assert.Equal(t, []string{"a"}, stringList("a"))
	assert.Equal(t, []string{"a", "b"}, stringList([]string{" a ", "", "b"}))
	assert.Nil(t, stringList(nil))
	assert.Nil(t, stringList(12))
	assert.Nil(t, stringList(map[string]any{"a": "b"}))
}
