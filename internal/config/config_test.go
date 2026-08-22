package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErr    bool
		errSubstr  string
		wantListen string
		wantTarget string
	}{
		{
			name:       "valid minimal config",
			yaml:       "target: http://localhost:9000\n",
			wantListen: ":8080",
			wantTarget: "http://localhost:9000",
		},
		{
			name:       "valid config with all fields",
			yaml:       "listen_addr: \":9090\"\ntarget: https://backend.internal:8443\ntimeouts:\n  dial: 2s\n",
			wantListen: ":9090",
			wantTarget: "https://backend.internal:8443",
		},
		{
			name:      "missing target",
			yaml:      "listen_addr: \":8080\"\n",
			wantErr:   true,
			errSubstr: "target is required",
		},
		{
			name:    "relative target rejected",
			yaml:    "target: /just/a/path\n",
			wantErr: true,
		},
		{
			name:      "unsupported scheme rejected",
			yaml:      "target: ftp://backend:21\n",
			wantErr:   true,
			errSubstr: "scheme must be http or https",
		},
		{
			name:    "malformed yaml",
			yaml:    "target: [this is not valid\n",
			wantErr: true,
		},
		{
			name:    "bad listen_addr",
			yaml:    "listen_addr: \"not-a-host-port\"\ntarget: http://localhost:9000\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.yaml)
			cfg, err := loadLayered(path, nil)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.ErrorContains(t, err, tt.errSubstr)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantListen, cfg.ListenAddr)
			assert.Equal(t, tt.wantTarget, cfg.Target)
			require.NotNil(t, cfg.TargetURL())
			assert.Equal(t, tt.wantTarget, cfg.TargetURL().String())
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := loadLayered(filepath.Join(t.TempDir(), "does-not-exist.yaml"), nil)
	require.Error(t, err)
}

func TestApplyDefaults_TimeoutsRetainOverrides(t *testing.T) {
	path := writeTempConfig(t, "target: http://localhost:9000\ntimeouts:\n  dial: 2s\n  read: 45s\n")
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Second, cfg.Timeouts.Dial)
	assert.Equal(t, 45*time.Second, cfg.Timeouts.Read)
	// Untouched fields still get defaulted.
	assert.Equal(t, defaultWriteTimeout, cfg.Timeouts.Write)
	assert.Equal(t, defaultIdleTimeout, cfg.Timeouts.Idle)
	assert.Equal(t, defaultReadHeaderTimeout, cfg.Timeouts.ReadHeader)
	assert.Equal(t, defaultResponseHeaderTimeout, cfg.Timeouts.ResponseHeader)
}

// TestLoad_AuthSourcesRoundTrip is the concrete proof that koanf/
// mapstructure correctly decodes two differently-shaped YAML
// lists-of-maps — including one with a nested list-of-structs field —
// into []JWTSource/[]SAMLSource, not just an assumption.
func TestLoad_AuthSourcesRoundTrip(t *testing.T) {
	t.Setenv("TAP_TEST_SAML_SESSION_KEY", validSAMLSessionKey)

	yamlConfig := `
target: http://localhost:9000
inbound:
  auth:
    jwt:
      - issuer: https://issuer-a.example.com
        jwks_url: https://issuer-a.example.com/jwks.json
      - name: oidc-source
        issuer: https://issuer-b.example.com
        oidc_discovery_url: https://issuer-b.example.com/.well-known/openid-configuration
        jwks_cache_ttl: 10m
        disabled: true
        credentials:
          - location: header
            name: Authorization
            prefix: "Bearer "
          - location: cookie
            name: session
    saml:
      issuer: https://idp.example.com/metadata
      idp_metadata_url: https://idp.example.com/metadata
      sp_base_url: https://proxy.example.com
      sp_entity_id: https://proxy.example.com/saml/metadata
      acs_path: /saml/corp-sso/acs
      session_cookie: corp_sso_session
      session_signing_key_env: TAP_TEST_SAML_SESSION_KEY
`
	path := writeTempConfig(t, yamlConfig)
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 2)

	jwks := cfg.Inbound.Auth.JWT[0]
	assert.Equal(t, "https://issuer-a.example.com", jwks.Issuer)
	assert.Equal(t, "https://issuer-a.example.com", jwks.Name, "no name given - defaults to issuer")
	assert.Equal(t, "https://issuer-a.example.com/jwks.json", jwks.JWKSURL)
	assert.False(t, jwks.Disabled)
	assert.Equal(t, []string{"RS256"}, jwks.Algorithms, "defaulted")
	assert.Equal(t,
		[]CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}},
		jwks.Credentials, "defaulted")

	oidc := cfg.Inbound.Auth.JWT[1]
	assert.Equal(t, "oidc-source", oidc.Name, "explicit name overrides the issuer default")
	assert.Equal(t, "https://issuer-b.example.com", oidc.Issuer)
	assert.Equal(t, "https://issuer-b.example.com/.well-known/openid-configuration", oidc.OIDCDiscoveryURL)
	assert.True(t, oidc.Disabled)
	assert.Equal(t, 10*time.Minute, oidc.JWKSCacheTTL)
	require.Len(t, oidc.Credentials, 2)
	assert.Equal(t, CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "}, oidc.Credentials[0])
	assert.Equal(t, CredentialLocation{Location: "cookie", Name: "session"}, oidc.Credentials[1])

	require.NotNil(t, cfg.Inbound.Auth.SAML)
	saml := cfg.Inbound.Auth.SAML
	assert.Equal(t, "https://idp.example.com/metadata", saml.Name, "no name given - defaults to issuer")
	assert.Equal(t, "https://idp.example.com/metadata", saml.Issuer)
	assert.Equal(t, "https://idp.example.com/metadata", saml.IDPMetadataURL)
	assert.Equal(t, "https://proxy.example.com", saml.SPBaseURL)
	assert.Equal(t, "https://proxy.example.com/saml/metadata", saml.SPEntityID)
	assert.Equal(t, "/saml/corp-sso/acs", saml.ACSPath)
	assert.Equal(t, "corp_sso_session", saml.SessionCookie)
	assert.Equal(t, "TAP_TEST_SAML_SESSION_KEY", saml.SessionSigningKeyEnv)
	assert.Equal(t, defaultSessionDuration, saml.SessionDuration, "defaulted")
	assert.Equal(t, defaultIDPMetadataCacheTTL, saml.IDPMetadataCacheTTL, "defaulted")

	assert.True(t, cfg.Inbound.Auth.Enabled(), "the first jwt source and the saml source are both non-disabled")
}

func TestApplyDefaults_AllTimeoutsDefaulted(t *testing.T) {
	path := writeTempConfig(t, "target: http://localhost:9000\n")
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)

	assert.Equal(t, defaultReadHeaderTimeout, cfg.Timeouts.ReadHeader)
	assert.Equal(t, defaultReadTimeout, cfg.Timeouts.Read)
	assert.Equal(t, defaultWriteTimeout, cfg.Timeouts.Write)
	assert.Equal(t, defaultIdleTimeout, cfg.Timeouts.Idle)
	assert.Equal(t, defaultDialTimeout, cfg.Timeouts.Dial)
	assert.Equal(t, defaultResponseHeaderTimeout, cfg.Timeouts.ResponseHeader)
}
