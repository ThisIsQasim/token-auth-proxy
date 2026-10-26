package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigningKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func testSealingKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

// validOAuthConfig is a complete, valid proxy config with the OAuth server
// enabled, defaults applied.
func validOAuthConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		Target: "http://opensearch:9200",
		Inbound: InboundConfig{
			Auth: InboundAuthConfig{JWT: []JWTSource{validLoginSource()}},
			OAuthServer: &OAuthServerConfig{
				SPBaseURL:   "https://os.example.com",
				MCPURL:      "https://os.example.com/_plugins/_ml/mcp",
				SealingKeys: []string{testSealingKey(t)},
				Clients: []OAuthClient{
					{ID: "claude-code", RedirectURIs: []string{"http://localhost/callback"}},
					{ID: "claude-ai", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}},
				},
			}},
		Outbound: OutboundConfig{Token: &TokenConfig{
			SigningKeys: []SigningKey{{KID: "k1", PrivateKey: testSigningKeyPEM(t)}},
		}},
	}
	c.applyDefaults()
	return c
}

func TestOAuth_DefaultsAndAccessors(t *testing.T) {
	c := validOAuthConfig(t)
	require.NoError(t, c.Validate())
	require.True(t, c.OAuthEnabled())

	srv, tok := c.Inbound.OAuthServer, c.Outbound.Token
	assert.Equal(t, 60*time.Second, srv.CodeTTL)
	assert.Equal(t, 24*time.Hour, srv.RefreshAbsoluteLifetime)
	assert.Equal(t, 15*time.Minute, tok.AccessTokenTTL)
	assert.Equal(t, "https://os.example.com/_plugins/_ml/mcp", tok.Audience, "audience defaults to mcp_url")
	assert.Equal(t, TokenClaims{Subject: "sub", Email: "email", Groups: "groups"}, tok.Claims)

	assert.Equal(t, "https://os.example.com/_tap/oauth", srv.Issuer())
	assert.Equal(t, "https://os.example.com/_tap/oauth/protected-resource", srv.ProtectedResourceMetadataURL())
	require.Len(t, tok.Keys(), 1)
	assert.Equal(t, "k1", tok.Keys()[0].KID)
	require.Len(t, srv.SealingKeyBytes(), 1)
	assert.Len(t, srv.SealingKeyBytes()[0], 32)
}

func TestOAuth_NotConfigured(t *testing.T) {
	c := &Config{Target: "http://opensearch:9200"}
	c.applyDefaults()
	require.NoError(t, c.Validate())
	assert.False(t, c.OAuthEnabled())
}

func TestOAuth_DisabledIsNotEnabledButStillValidated(t *testing.T) {
	c := validOAuthConfig(t)
	c.Inbound.OAuthServer.Disabled = true
	require.NoError(t, c.Validate())
	assert.False(t, c.OAuthEnabled())

	c.Inbound.OAuthServer.MCPURL = ""
	assert.ErrorContains(t, c.Validate(), "mcp_url", "a disabled server is still checked, like a disabled source")
}

func TestOAuth_RequiresBothBlocks(t *testing.T) {
	c := validOAuthConfig(t)
	c.Outbound.Token = nil
	assert.ErrorContains(t, c.Validate(), "inbound.oauth_server requires outbound.token")

	c = validOAuthConfig(t)
	c.Inbound.OAuthServer = nil
	assert.ErrorContains(t, c.Validate(), "outbound.token requires inbound.oauth_server")
}

func TestOAuth_Validate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		errSub string
	}{
		{"missing sp_base_url", func(c *Config) { c.Inbound.OAuthServer.SPBaseURL = "" }, "sp_base_url is required"},
		{"sp_base_url with query", func(c *Config) { c.Inbound.OAuthServer.SPBaseURL = "https://os.example.com/?x=1" }, "no query"},
		{"sp_base_url with path", func(c *Config) { c.Inbound.OAuthServer.SPBaseURL = "https://os.example.com/proxy" }, "no path"},
		{"missing mcp_url", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "" }, "mcp_url is required"},
		{"mcp_url other host", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "https://other.example.com/mcp" }, "must share sp_base_url's origin"},
		{"mcp_url other scheme", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "http://os.example.com/mcp" }, "must share sp_base_url's origin"},
		{"mcp_url without path", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "https://os.example.com" }, "must name the MCP endpoint path"},
		{"mcp_url under oauth prefix", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "https://os.example.com/_tap/oauth/x" }, "serves itself"},
		{"mcp_url on logout", func(c *Config) { c.Inbound.OAuthServer.MCPURL = "https://os.example.com/_tap/logout" }, "serves itself"},
		{"code_ttl too short", func(c *Config) { c.Inbound.OAuthServer.CodeTTL = time.Second }, "code_ttl"},
		{"code_ttl too long", func(c *Config) { c.Inbound.OAuthServer.CodeTTL = time.Hour }, "code_ttl"},
		{"refresh lifetime too long", func(c *Config) { c.Inbound.OAuthServer.RefreshAbsoluteLifetime = 400 * 24 * time.Hour }, "refresh_absolute_lifetime"},
		{"no sealing keys", func(c *Config) { c.Inbound.OAuthServer.SealingKeys = nil }, "sealing_keys requires"},
		{"sealing key not base64", func(c *Config) { c.Inbound.OAuthServer.SealingKeys = []string{"!!!"} }, "base64"},
		{"sealing key wrong length", func(c *Config) {
			c.Inbound.OAuthServer.SealingKeys = []string{base64.StdEncoding.EncodeToString([]byte("short"))}
		}, "32 bytes"},
		{"no clients", func(c *Config) { c.Inbound.OAuthServer.Clients = nil }, "clients requires"},
		{"client without id", func(c *Config) { c.Inbound.OAuthServer.Clients[0].ID = "" }, "id is required"},
		{"duplicate client", func(c *Config) { c.Inbound.OAuthServer.Clients[1].ID = "claude-code" }, "already used"},
		{"client without redirects", func(c *Config) { c.Inbound.OAuthServer.Clients[0].RedirectURIs = nil }, "redirect_uris requires"},
		{"http redirect off loopback", func(c *Config) {
			c.Inbound.OAuthServer.Clients[0].RedirectURIs = []string{"http://evil.example.com/cb"}
		}, "only allowed for localhost"},
		{"redirect with fragment", func(c *Config) {
			c.Inbound.OAuthServer.Clients[0].RedirectURIs = []string{"https://a.example.com/cb#x"}
		}, "fragment"},
		{"custom scheme redirect", func(c *Config) { c.Inbound.OAuthServer.Clients[0].RedirectURIs = []string{"app://cb"} }, "scheme must be http or https"},
		{"empty denylist subject", func(c *Config) { c.Inbound.OAuthServer.Denylist.Subjects = []string{" "} }, "denylist.subjects[0]"},

		{"no signing keys", func(c *Config) { c.Outbound.Token.SigningKeys = nil }, "signing_keys requires"},
		{"signing key without kid", func(c *Config) { c.Outbound.Token.SigningKeys[0].KID = "" }, "kid is required"},
		{"duplicate kid", func(c *Config) {
			c.Outbound.Token.SigningKeys = append(c.Outbound.Token.SigningKeys, c.Outbound.Token.SigningKeys[0])
		}, "already used"},
		{"signing key not PEM", func(c *Config) { c.Outbound.Token.SigningKeys[0].PrivateKey = "nope" }, "not PEM"},
		{"access ttl too short", func(c *Config) { c.Outbound.Token.AccessTokenTTL = time.Second }, "access_token_ttl"},
		{"access ttl too long", func(c *Config) { c.Outbound.Token.AccessTokenTTL = 24 * time.Hour }, "access_token_ttl"},
		{"bad audience", func(c *Config) { c.Outbound.Token.Audience = "not a url" }, "audience"},
		{"blank claim name", func(c *Config) { c.Outbound.Token.Claims.Groups = " " }, "claims.groups"},

		{"reserved jwt name", func(c *Config) {
			j := JWTSource{Name: OAuthSourceName, Issuer: "https://idp.example.com", JWKSURL: "https://idp.example.com/jwks"}
			j.applyDefaults()
			c.Inbound.Auth.JWT = []JWTSource{j}
		}, "reserved"},
		{"login callback under oauth prefix", func(c *Config) {
			j := validLoginSource()
			j.Login.CallbackPath = "/_tap/oauth/cb"
			c.Inbound.Auth.JWT = []JWTSource{j}
		}, "served by inbound.oauth_server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validOAuthConfig(t)
			tt.mutate(c)
			assert.ErrorContains(t, c.Validate(), tt.errSub)
		})
	}
}

func TestOAuth_SigningKeyFormats(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)
	sec1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)

	c := validOAuthConfig(t)
	c.Outbound.Token.SigningKeys = []SigningKey{{KID: "sec1", PrivateKey: sec1PEM}, {KID: "pkcs8", PrivateKey: testSigningKeyPEM(t)}}
	require.NoError(t, c.Validate())
	assert.Len(t, c.Outbound.Token.Keys(), 2)
	assert.Equal(t, "sec1", c.Outbound.Token.Keys()[0].KID, "configuration order is kept: the first key signs")

	c.Outbound.Token.SigningKeys = []SigningKey{{KID: "p384", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}))}}
	assert.ErrorContains(t, c.Validate(), "P-256")

	c.Outbound.Token.SigningKeys = []SigningKey{{KID: "cert", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))}}
	assert.ErrorContains(t, c.Validate(), "PEM type")
}

func TestOAuth_SealingKeyEncodings(t *testing.T) {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	for name, s := range map[string]string{
		"std":           base64.StdEncoding.EncodeToString(raw),
		"raw std":       base64.RawStdEncoding.EncodeToString(raw),
		"url":           base64.URLEncoding.EncodeToString(raw),
		"raw url":       base64.RawURLEncoding.EncodeToString(raw),
		"trailing line": base64.StdEncoding.EncodeToString(raw) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeSealingKey(s)
			require.NoError(t, err)
			assert.Equal(t, raw, got)
		})
	}
}

func TestOAuth_ACLSource(t *testing.T) {
	rule := ACLRule{
		Principals: []ACLPrincipal{{Mode: ACLModeJWT, Source: OAuthSourceName, Claims: map[string]string{"groups": "os-mcp-readers"}}},
		Paths:      []string{"/_plugins/_ml/mcp"},
	}

	c := validOAuthConfig(t)
	c.ACL = []ACLRule{rule}
	require.NoError(t, c.Validate(), "the proxy's own tokens can be named in an ACL rule")

	c.Inbound.OAuthServer.Disabled = true
	assert.NoError(t, c.Validate(), "and stays valid while the server is switched off, so switching it off cannot fail a reload")

	c.Inbound.OAuthServer, c.Outbound.Token = nil, nil
	assert.ErrorContains(t, c.Validate(), "does not name a configured", "but there is no such source once the server is gone")
}

func TestOAuth_DenylistContains(t *testing.T) {
	d := OAuthDenylist{Subjects: []string{"alice", "bob"}}
	assert.True(t, d.Contains("alice"))
	assert.False(t, d.Contains("carol"))
	assert.False(t, OAuthDenylist{}.Contains("alice"))
}

func oauthYAML(srvKey, sealPath, keyPath string) string {
	return fmt.Sprintf(`target: http://opensearch:9200
inbound:
  auth:
    jwt:
      - issuer: https://idp.example.com
        oidc_discovery_url: https://idp.example.com/.well-known/openid-configuration
        login:
          client_id: proxy
          sp_base_url: https://os.example.com
  oauth_server:
    sp_base_url: https://os.example.com
    mcp_url: https://os.example.com/_plugins/_ml/mcp
    code_ttl: 45s
    sealing_keys:
      - ${file:%s}
    clients:
      - id: claude-code
        redirect_uris:
          - http://localhost/callback
    denylist:
      subjects:
        - former@example.com
outbound:
  token:
    signing_keys:
      - kid: %s
        private_key: ${file:%s}
    access_token_ttl: 10m
`, sealPath, srvKey, keyPath)
}

func TestOAuth_LoadYAMLWithFileReferences(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.pem")
	sealPath := filepath.Join(dir, "seal.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(testSigningKeyPEM(t)), 0o600))
	require.NoError(t, os.WriteFile(sealPath, []byte(testSealingKey(t)+"\n"), 0o600))

	cfg, err := loadLayered(writeTempFile(t, oauthYAML("2026-10", sealPath, keyPath)), nil)
	require.NoError(t, err)

	assert.True(t, cfg.OAuthEnabled())
	assert.Equal(t, 45*time.Second, cfg.Inbound.OAuthServer.CodeTTL)
	assert.Equal(t, 10*time.Minute, cfg.Outbound.Token.AccessTokenTTL)
	assert.True(t, cfg.Inbound.OAuthServer.Denylist.Contains("former@example.com"))
	require.Len(t, cfg.Outbound.Token.Keys(), 1)
	assert.Equal(t, "2026-10", cfg.Outbound.Token.Keys()[0].KID)
}

func TestOAuth_JSONOverrides(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.pem")
	sealPath := filepath.Join(dir, "seal.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(testSigningKeyPEM(t)), 0o600))
	require.NoError(t, os.WriteFile(sealPath, []byte(testSealingKey(t)), 0o600))
	path := writeTempFile(t, oauthYAML("from-file", sealPath, keyPath))

	t.Run("denylist replaced by the flag", func(t *testing.T) {
		srv := fmt.Sprintf(`{"sp_base_url":"https://os.example.com","mcp_url":"https://os.example.com/_plugins/_ml/mcp",`+
			`"sealing_keys":[%q],"clients":[{"id":"c","redirect_uris":["http://localhost/cb"]}],"denylist":{"subjects":["flag@example.com"]}}`, testSealingKey(t))
		cfg, err := loadLayered(path, newFlagSet(t, "--inbound-oauth-server-json", srv))
		require.NoError(t, err)
		assert.True(t, cfg.Inbound.OAuthServer.Denylist.Contains("flag@example.com"))
		assert.False(t, cfg.Inbound.OAuthServer.Denylist.Contains("former@example.com"), "the override replaces the file's block outright")
		assert.Equal(t, "c", cfg.Inbound.OAuthServer.Clients[0].ID)
	})

	t.Run("token from the environment", func(t *testing.T) {
		tok := fmt.Sprintf(`{"signing_keys":[{"kid":"env","private_key":%q}],"access_token_ttl":"5m"}`, testSigningKeyPEM(t))
		t.Setenv("TAP_OUTBOUND_TOKEN_JSON", tok)
		cfg, err := loadLayered(path, newFlagSet(t))
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, cfg.Outbound.Token.AccessTokenTTL)
		assert.Equal(t, "env", cfg.Outbound.Token.Keys()[0].KID)
	})
}

func TestOAuth_DerivedJWTSource(t *testing.T) {
	c := validOAuthConfig(t)
	require.NoError(t, c.Validate())

	require.Len(t, c.Inbound.Auth.JWT, 2, "the login source plus the derived one")
	src := c.Inbound.Auth.JWT[1]
	assert.True(t, src.Local)
	assert.Equal(t, OAuthSourceName, src.Name)
	assert.Equal(t, "https://os.example.com/_tap/oauth", src.Issuer)
	assert.Equal(t, []string{"https://os.example.com/_plugins/_ml/mcp"}, src.Audiences)
	assert.Equal(t, []string{"ES256"}, src.Algorithms)
	assert.Equal(t, []CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}}, src.Credentials)
	assert.Empty(t, src.JWKSURL, "its keys are in-process")

	found := c.Inbound.Auth.JWTSourcesByIssuer("https://os.example.com/_tap/oauth")
	require.Len(t, found, 1, "tokens are routed to it by issuer like any other")
	assert.Equal(t, OAuthSourceName, found[0].Name)
}

func TestOAuth_NoDerivedSourceWhenOff(t *testing.T) {
	c := validOAuthConfig(t)
	c.Inbound.OAuthServer.Disabled = true
	require.NoError(t, c.Validate())
	require.Len(t, c.Inbound.Auth.JWT, 2)
	assert.True(t, c.Inbound.Auth.JWT[1].Disabled, "a disabled server's source is there but takes no part")
	assert.Empty(t, c.Inbound.Auth.JWTSourcesByIssuer(c.Inbound.OAuthServer.Issuer()), "and no token is routed to it")

	plain := &Config{Target: "http://opensearch:9200"}
	plain.applyDefaults()
	require.NoError(t, plain.Validate())
	assert.Empty(t, plain.Inbound.Auth.JWT)
}

func TestOAuth_ValidateIsIdempotent(t *testing.T) {
	c := validOAuthConfig(t)
	for range 3 {
		require.NoError(t, c.Validate())
	}
	assert.Len(t, c.Inbound.Auth.JWT, 2, "one derived source however often it is validated")

	c.Inbound.OAuthServer.Disabled = true
	require.NoError(t, c.Validate())
	assert.Len(t, c.Inbound.Auth.JWT, 2, "and it is still one when the server is turned off")
	assert.True(t, c.Inbound.Auth.JWT[1].Disabled)

	c.Inbound.OAuthServer, c.Outbound.Token = nil, nil
	require.NoError(t, c.Validate())
	assert.Len(t, c.Inbound.Auth.JWT, 1, "it goes away only when the server is gone")
}

func TestOAuth_RequiresALoginMethod(t *testing.T) {
	c := validOAuthConfig(t)
	c.Inbound.Auth.JWT = nil
	assert.ErrorContains(t, c.Validate(), "needs a way for people to log in")

	c.Inbound.Auth.Basic = &BasicSource{}
	c.Inbound.Auth.applyDefaults()
	err := c.Validate()
	assert.NotContains(t, fmt.Sprint(err), "needs a way for people to log in", "basic counts as a way to log in")

	c.Inbound.OAuthServer.Disabled = true
	c.Inbound.Auth.Basic = nil
	assert.NoError(t, c.Validate(), "a disabled server needs none")
}

// Local is set by the proxy alone: a source that arrives marked Local (it has no
// yaml tag) is dropped, so configuration cannot claim the in-process keys.
func TestOAuth_LocalSourceIsNotConfigurable(t *testing.T) {
	src := JWTSource{Name: "mine", Issuer: "https://idp.example.com", JWKSURL: "https://idp.example.com/jwks", Local: true}
	c := validOAuthConfig(t)
	c.Inbound.Auth.JWT = append(c.Inbound.Auth.JWT, src)
	require.NoError(t, c.Validate())
	for _, j := range c.Inbound.Auth.JWT {
		if j.Name == "mine" {
			t.Fatal("a source marked Local by hand is dropped on validation, only the derived one stays")
		}
	}
}
