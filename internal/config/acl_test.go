package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const aclFileBase = `
target: http://backend:9000
inbound:
  auth:
    jwt:
      - name: ci
        issuer: https://issuer.example.com
        jwks_url: https://issuer.example.com/jwks.json
    basic:
      users:
        - username: alice
          password_hash: "$2a$04$G1ZcOXdxWqJWh2MVwSj2FOPQhOZc6oGmFHqbYn.9UwuoYNO7GeU4K"
`

func TestLoad_ACLAtRoot(t *testing.T) {
	path := writeTempFile(t, aclFileBase+`
acl:
  - principals:
      - mode: basic
        subject: alice
      - mode: jwt
        source: ci
        claims:
          https://example.com/roles: admin
          kubernetes.io: x
    methods:
      - get
      - Post
    paths:
      - /api/v1/push
      - /api/*
  - principals:
      - mode: saml
        subject: carol@example.com
`)
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)

	require.Len(t, cfg.ACL, 2)
	r := cfg.ACL[0]
	assert.Equal(t, []string{"GET", "POST"}, r.Methods, "methods are uppercased by applyDefaults")
	assert.Equal(t, []string{"/api/v1/push", "/api/*"}, r.Paths)
	require.Len(t, r.Principals, 2)
	assert.Equal(t, ACLPrincipal{Mode: "basic", Subject: "alice"}, r.Principals[0])
	assert.Equal(t, map[string]string{"https://example.com/roles": "admin", "kubernetes.io": "x"}, r.Principals[1].Claims,
		"claim names containing dots survive koanf's key delimiter")
	assert.Empty(t, cfg.ACL[1].Methods, "omitted methods stay empty, meaning all methods")
	assert.Empty(t, cfg.ACL[1].Paths, "omitted paths stay empty, meaning all paths")
}

func TestLoad_ACLUnderInboundRejected(t *testing.T) {
	path := writeTempFile(t, aclFileBase+`
  acl:
    - principals:
        - mode: basic
          subject: alice
`)
	_, err := loadLayered(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acl belongs at the top level")
}

func TestLoad_NoACL(t *testing.T) {
	path := writeTempFile(t, aclFileBase)
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)
	assert.Empty(t, cfg.ACL)
}

func TestLoadLayered_ACLJSONOverride(t *testing.T) {
	path := writeTempFile(t, aclFileBase+`
acl:
  - principals:
      - mode: saml
        subject: from-file
  - principals:
      - mode: saml
        subject: from-file-2
`)
	envACL := `[{"principals":[{"mode":"saml","subject":"from-env"}],"methods":["*"]}]`
	flagACL := `[{"principals":[{"mode":"basic","subject":"alice"}],"paths":["/flag"]}]`

	t.Run("file only", func(t *testing.T) {
		cfg, err := loadLayered(path, newFlagSet(t))
		require.NoError(t, err)
		require.Len(t, cfg.ACL, 2)
		assert.Equal(t, "from-file", cfg.ACL[0].Principals[0].Subject)
	})

	t.Run("env replaces file", func(t *testing.T) {
		t.Setenv("TAP_ACL_JSON", envACL)
		cfg, err := loadLayered(path, newFlagSet(t))
		require.NoError(t, err)
		require.Len(t, cfg.ACL, 1, "the override fully replaces the file's list")
		assert.Equal(t, "from-env", cfg.ACL[0].Principals[0].Subject)
		assert.Equal(t, []string{"*"}, cfg.ACL[0].Methods)
	})

	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv("TAP_ACL_JSON", envACL)
		cfg, err := loadLayered(path, newFlagSet(t, "--acl-json", flagACL))
		require.NoError(t, err)
		require.Len(t, cfg.ACL, 1)
		assert.Equal(t, "alice", cfg.ACL[0].Principals[0].Subject)
		assert.Equal(t, []string{"/flag"}, cfg.ACL[0].Paths)
	})

	t.Run("invalid override fails the load", func(t *testing.T) {
		t.Setenv("TAP_ACL_JSON", `[{"principals":[{"mode":"basic","subject":"nobody"}]}]`)
		_, err := loadLayered(path, newFlagSet(t))
		require.Error(t, err)
	})
}

// aclTestConfig is a valid config with a JWT source "ci" and a Basic user
// "alice" for ACL rules to reference.
func aclTestConfig(rules ...ACLRule) *Config {
	j := validJWTSource()
	j.Name = "ci"
	c := &Config{
		Target: "http://backend:9000",
		Inbound: InboundConfig{Auth: InboundAuthConfig{
			JWT:   []JWTSource{j},
			Basic: &BasicSource{Users: []BasicUser{{Username: "alice", PasswordHash: "$2a$04$G1ZcOXdxWqJWh2MVwSj2FOPQhOZc6oGmFHqbYn.9UwuoYNO7GeU4K"}}},
		}},
		ACL: rules,
	}
	c.applyDefaults()
	return c
}

func principalRule(p ACLPrincipal) ACLRule {
	return ACLRule{Principals: []ACLPrincipal{p}}
}

func TestValidateACL(t *testing.T) {
	alice := ACLPrincipal{Mode: "basic", Subject: "alice"}

	for _, tc := range []struct {
		name    string
		rule    ACLRule
		wantErr string
	}{
		{name: "basic subject", rule: principalRule(alice)},
		{name: "jwt source only", rule: principalRule(ACLPrincipal{Mode: "jwt", Source: "ci"})},
		{name: "jwt subject only", rule: principalRule(ACLPrincipal{Mode: "jwt", Subject: "bot"})},
		{name: "jwt claims only", rule: principalRule(ACLPrincipal{Mode: "jwt", Claims: map[string]string{"g": "x"}})},
		{name: "saml subject", rule: principalRule(ACLPrincipal{Mode: "saml", Subject: "carol"})},
		{name: "saml claims", rule: principalRule(ACLPrincipal{Mode: "saml", Claims: map[string]string{"groups": "admins"}})},
		{name: "wildcard method", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{"*"}}},
		{name: "named methods", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{"GET", "PROPFIND"}}},
		{name: "exact and prefix paths", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"/", "/a/b", "/a/", "/*", "/a/*"}}},

		{name: "invalid mode", rule: principalRule(ACLPrincipal{Mode: "oauth", Subject: "x"}), wantErr: "mode"},
		{name: "empty mode", rule: principalRule(ACLPrincipal{Subject: "x"}), wantErr: "mode"},
		{name: "source on basic", rule: principalRule(ACLPrincipal{Mode: "basic", Subject: "alice", Source: "ci"}), wantErr: "source is only valid"},
		{name: "source on saml", rule: principalRule(ACLPrincipal{Mode: "saml", Source: "ci"}), wantErr: "source is only valid"},
		{name: "unknown jwt source", rule: principalRule(ACLPrincipal{Mode: "jwt", Source: "nope"}), wantErr: "does not name a configured"},
		{name: "unknown basic user", rule: principalRule(ACLPrincipal{Mode: "basic", Subject: "mallory"}), wantErr: "not a configured inbound.auth.basic user"},
		{name: "claims on basic", rule: principalRule(ACLPrincipal{Mode: "basic", Subject: "alice", Claims: map[string]string{"g": "x"}}), wantErr: "claims are not available"},
		{name: "principal with only mode", rule: principalRule(ACLPrincipal{Mode: "jwt"}), wantErr: "at least one of source, subject or claims"},
		{name: "empty claim name", rule: principalRule(ACLPrincipal{Mode: "jwt", Claims: map[string]string{"": "x"}}), wantErr: "claim name"},
		{name: "empty principals", rule: ACLRule{Methods: []string{"GET"}}, wantErr: "principals is required"},

		{name: "path without leading slash", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"api"}}, wantErr: "must begin with"},
		{name: "star mid path", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"/a/*/b"}}, wantErr: "only allowed as a trailing"},
		{name: "star glued to segment", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"/api*"}}, wantErr: "only allowed as a trailing"},
		{name: "bare star path", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"*"}}, wantErr: "must begin with"},
		{name: "unclean path", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"/a/../b"}}, wantErr: "clean path"},
		{name: "double slash path", rule: ACLRule{Principals: []ACLPrincipal{alice}, Paths: []string{"/a//b"}}, wantErr: "clean path"},

		{name: "invalid method token", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{"GE T"}}, wantErr: "not a valid HTTP method"},
		{name: "empty method", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{""}}, wantErr: "not a valid HTTP method"},
		{name: "glob method", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{"P*"}}, wantErr: "not a valid HTTP method"},
		{name: "wildcard mixed with named", rule: ACLRule{Principals: []ACLPrincipal{alice}, Methods: []string{"GET", "*"}}, wantErr: "can't be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := aclTestConfig(tc.rule).Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Contains(t, err.Error(), "acl[0]")
		})
	}
}

func TestApplyDefaults_ACLMethodsUppercased(t *testing.T) {
	c := aclTestConfig(ACLRule{Principals: []ACLPrincipal{{Mode: "basic", Subject: "alice"}}, Methods: []string{"get", "pAtCh"}})
	assert.Equal(t, []string{"GET", "PATCH"}, c.ACL[0].Methods)
}

func TestValidateACL_NoAuthEnabledStillLoads(t *testing.T) {
	c := &Config{
		Target: "http://backend:9000",
		ACL:    []ACLRule{principalRule(ACLPrincipal{Mode: "saml", Subject: "carol"})},
	}
	c.applyDefaults()
	require.NoError(t, c.Validate(), "a hot-reload may disable every source; that denies at runtime rather than failing the load")

	j := validJWTSource()
	j.Name = "ci"
	j.Disabled = true
	c.Inbound.Auth.JWT = []JWTSource{j}
	c.ACL = []ACLRule{principalRule(ACLPrincipal{Mode: "jwt", Source: "ci"})}
	require.NoError(t, c.Validate(), "a disabled source can still be referenced")
}

func TestIsCleanPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":       true,
		"/a":      true,
		"/a/":     true,
		"/a/b/":   true,
		"/a//":    false,
		"//a":     false,
		"/a/./b":  false,
		"/a/../b": false,
		"/..":     false,
		"/a/.":    false,
	} {
		assert.Equal(t, want, IsCleanPath(p), p)
	}
}
