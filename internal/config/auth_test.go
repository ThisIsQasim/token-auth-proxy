package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validJWTSource returns a fresh, already-defaulted, valid JWTSource,
// so each test only needs to mutate the one field it cares about.
func validJWTSource() JWTSource {
	j := JWTSource{
		Name:    "jwt-a",
		Issuer:  "https://issuer.example.com",
		JWKSURL: "https://issuer.example.com/jwks.json",
	}
	j.applyDefaults()
	return j
}

// validSAMLSource returns a fresh, already-defaulted, valid SAMLSource
// whose SessionSigningKeyEnv is guaranteed set via t.Setenv.
func validSAMLSource(t *testing.T) SAMLSource {
	t.Helper()
	t.Setenv("SAML_TEST_SESSION_KEY", "secret")
	s := SAMLSource{
		Name:                 "saml-a",
		Issuer:               "https://idp.example.com/metadata",
		IDPMetadataURL:       "https://idp.example.com/metadata",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/saml-a/acs",
		SessionCookie:        "saml_a_session",
		SessionSigningKeyEnv: "SAML_TEST_SESSION_KEY",
	}
	s.applyDefaults()
	return s
}

func TestJWTSource_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*JWTSource)
		wantErr   bool
		errSubstr string
	}{
		{name: "valid, algorithms omitted", mutate: func(j *JWTSource) {}},
		{
			name: "valid, credentials omitted",
			mutate: func(j *JWTSource) {
				j.Credentials = nil
				j.applyDefaults()
			},
		},
		{
			name:      "missing name",
			mutate:    func(j *JWTSource) { j.Name = "" },
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name:      "missing issuer",
			mutate:    func(j *JWTSource) { j.Issuer = "" },
			wantErr:   true,
			errSubstr: "issuer is required",
		},
		{
			name: "both jwks_url and oidc_discovery_url set",
			mutate: func(j *JWTSource) {
				j.OIDCDiscoveryURL = "https://issuer.example.com/.well-known/openid-configuration"
			},
			wantErr:   true,
			errSubstr: "mutually exclusive",
		},
		{
			name: "neither jwks_url nor oidc_discovery_url set",
			mutate: func(j *JWTSource) {
				j.JWKSURL = ""
			},
			wantErr:   true,
			errSubstr: "one of jwks_url or oidc_discovery_url is required",
		},
		{
			name:      "relative jwks_url",
			mutate:    func(j *JWTSource) { j.JWKSURL = "/jwks.json" },
			wantErr:   true,
			errSubstr: "jwks_url",
		},
		{
			name:      "wrong-scheme jwks_url",
			mutate:    func(j *JWTSource) { j.JWKSURL = "ftp://issuer.example.com/jwks.json" },
			wantErr:   true,
			errSubstr: "scheme must be http or https",
		},
		{
			name:      "algorithms: none",
			mutate:    func(j *JWTSource) { j.Algorithms = []string{"none"} },
			wantErr:   true,
			errSubstr: "not a supported algorithm",
		},
		{
			name:      "algorithms: HS256",
			mutate:    func(j *JWTSource) { j.Algorithms = []string{"HS256"} },
			wantErr:   true,
			errSubstr: "not a supported algorithm",
		},
		{
			name:      "algorithms: mixed good and bad",
			mutate:    func(j *JWTSource) { j.Algorithms = []string{"RS256", "none"} },
			wantErr:   true,
			errSubstr: "not a supported algorithm",
		},
		{
			name: "credentials: invalid location",
			mutate: func(j *JWTSource) {
				j.Credentials = []CredentialLocation{{Location: "body", Name: "token"}}
			},
			wantErr:   true,
			errSubstr: "must be one of header, cookie, query",
		},
		{
			name: "credentials: empty name",
			mutate: func(j *JWTSource) {
				j.Credentials = []CredentialLocation{{Location: "header", Name: ""}}
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "credentials: one valid, one invalid still errors",
			mutate: func(j *JWTSource) {
				j.Credentials = []CredentialLocation{
					{Location: "header", Name: "Authorization"},
					{Location: "body", Name: "token"},
				}
			},
			wantErr:   true,
			errSubstr: "must be one of header, cookie, query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := validJWTSource()
			tt.mutate(&j)
			err := j.validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.ErrorContains(t, err, tt.errSubstr)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSAMLSource_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*SAMLSource)
		wantErr   bool
		errSubstr string
	}{
		{name: "valid"},
		{name: "missing name", mutate: func(s *SAMLSource) { s.Name = "" }, wantErr: true, errSubstr: "name is required"},
		{name: "missing issuer", mutate: func(s *SAMLSource) { s.Issuer = "" }, wantErr: true, errSubstr: "issuer is required"},
		{
			name: "missing idp_metadata_url", mutate: func(s *SAMLSource) { s.IDPMetadataURL = "" },
			wantErr: true, errSubstr: "idp_metadata_url is required",
		},
		{
			name: "missing sp_entity_id", mutate: func(s *SAMLSource) { s.SPEntityID = "" },
			wantErr: true, errSubstr: "sp_entity_id is required",
		},
		{
			name: "missing acs_path", mutate: func(s *SAMLSource) { s.ACSPath = "" },
			wantErr: true, errSubstr: "acs_path is required",
		},
		{
			name: "missing session_cookie", mutate: func(s *SAMLSource) { s.SessionCookie = "" },
			wantErr: true, errSubstr: "session_cookie is required",
		},
		{
			name: "missing session_signing_key_env", mutate: func(s *SAMLSource) { s.SessionSigningKeyEnv = "" },
			wantErr: true, errSubstr: "session_signing_key_env is required",
		},
		{
			name: "session_signing_key_env names an unset env var",
			mutate: func(s *SAMLSource) {
				s.SessionSigningKeyEnv = "SAML_TEST_SESSION_KEY_NOT_SET"
			},
			wantErr: true, errSubstr: "is not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Explicitly prove the env var is absent, rather than
			// relying on it merely never having been set by another
			// test: t.Setenv guarantees a clean value is in place for
			// the duration of the test and is restored afterward, then
			// os.Unsetenv removes it entirely.
			t.Setenv("SAML_TEST_SESSION_KEY_NOT_SET", "placeholder")
			require.NoError(t, os.Unsetenv("SAML_TEST_SESSION_KEY_NOT_SET"))

			s := validSAMLSource(t)
			if tt.mutate != nil {
				tt.mutate(&s)
			}
			err := s.validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.ErrorContains(t, err, tt.errSubstr)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestInboundAuthConfig_Validate(t *testing.T) {
	t.Run("valid multi-source, mixing disabled", func(t *testing.T) {
		jwt := validJWTSource()
		saml := validSAMLSource(t)
		disabledJWT := validJWTSource()
		disabledJWT.Name = "jwt-b"
		disabledJWT.Issuer = "https://issuer-b.example.com"
		disabledJWT.Disabled = true

		a := InboundAuthConfig{JWT: []JWTSource{jwt, disabledJWT}, SAML: &saml}
		assert.NoError(t, a.Validate())
	})

	t.Run("duplicate name across jwt and saml", func(t *testing.T) {
		jwt := validJWTSource()
		saml := validSAMLSource(t)
		saml.Name = jwt.Name

		a := InboundAuthConfig{JWT: []JWTSource{jwt}, SAML: &saml}
		assert.ErrorContains(t, a.Validate(), "name")
	})

	t.Run("duplicate issuer across jwt and saml", func(t *testing.T) {
		jwt := validJWTSource()
		saml := validSAMLSource(t)
		saml.Issuer = jwt.Issuer

		a := InboundAuthConfig{JWT: []JWTSource{jwt}, SAML: &saml}
		assert.ErrorContains(t, a.Validate(), "issuer")
	})

	t.Run("no saml source configured", func(t *testing.T) {
		jwt := validJWTSource()
		a := InboundAuthConfig{JWT: []JWTSource{jwt}}
		assert.NoError(t, a.Validate(), "a nil SAML source must not be validated or otherwise rejected")
	})
}

func TestInboundAuthConfig_Enabled(t *testing.T) {
	tests := []struct {
		name string
		a    InboundAuthConfig
		want bool
	}{
		{name: "zero sources", a: InboundAuthConfig{}, want: false},
		{
			name: "one non-disabled jwt source",
			a:    InboundAuthConfig{JWT: []JWTSource{{Name: "j"}}},
			want: true,
		},
		{
			name: "a non-disabled saml source",
			a:    InboundAuthConfig{SAML: &SAMLSource{Name: "s"}},
			want: true,
		},
		{
			name: "a disabled saml source, no jwt sources",
			a:    InboundAuthConfig{SAML: &SAMLSource{Name: "s", Disabled: true}},
			want: false,
		},
		{
			name: "every source disabled",
			a: InboundAuthConfig{
				JWT:  []JWTSource{{Name: "j", Disabled: true}},
				SAML: &SAMLSource{Name: "s", Disabled: true},
			},
			want: false,
		},
		{
			name: "mix of disabled and non-disabled",
			a: InboundAuthConfig{
				JWT:  []JWTSource{{Name: "j", Disabled: true}},
				SAML: &SAMLSource{Name: "s", Disabled: false},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.Enabled())
		})
	}
}

func TestJWTSource_ApplyDefaults(t *testing.T) {
	t.Run("all zero/empty fields get defaulted", func(t *testing.T) {
		var j JWTSource
		j.applyDefaults()

		assert.Equal(t, defaultJWKSCacheTTL, j.JWKSCacheTTL)
		assert.Equal(t, defaultClockSkew, j.ClockSkew)
		assert.Equal(t, []string{defaultAlgorithm}, j.Algorithms)
		assert.Equal(t, []CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}}, j.Credentials)
	})

	t.Run("explicit values survive untouched", func(t *testing.T) {
		j := JWTSource{
			JWKSCacheTTL: 10 * time.Minute,
			ClockSkew:    5 * time.Second,
			Algorithms:   []string{"ES256"},
			Credentials:  []CredentialLocation{{Location: "cookie", Name: "token"}},
		}
		j.applyDefaults()

		assert.Equal(t, 10*time.Minute, j.JWKSCacheTTL)
		assert.Equal(t, 5*time.Second, j.ClockSkew)
		assert.Equal(t, []string{"ES256"}, j.Algorithms)
		assert.Equal(t, []CredentialLocation{{Location: "cookie", Name: "token"}}, j.Credentials)
	})
}

func TestSAMLSource_ApplyDefaults(t *testing.T) {
	t.Run("zero session_duration gets defaulted", func(t *testing.T) {
		var s SAMLSource
		s.applyDefaults()
		assert.Equal(t, defaultSessionDuration, s.SessionDuration)
	})

	t.Run("explicit session_duration survives", func(t *testing.T) {
		s := SAMLSource{SessionDuration: 8 * time.Hour}
		s.applyDefaults()
		assert.Equal(t, 8*time.Hour, s.SessionDuration)
	})
}

func TestInboundAuthConfig_JWTSourceByIssuer(t *testing.T) {
	enabled := JWTSource{Name: "enabled", Issuer: "https://enabled.example.com"}
	disabled := JWTSource{Name: "disabled", Issuer: "https://disabled.example.com", Disabled: true}
	a := InboundAuthConfig{JWT: []JWTSource{enabled, disabled}}

	got, ok := a.JWTSourceByIssuer("https://enabled.example.com")
	require.True(t, ok)
	assert.Equal(t, "enabled", got.Name)

	_, ok = a.JWTSourceByIssuer("https://unknown.example.com")
	assert.False(t, ok)

	_, ok = a.JWTSourceByIssuer("https://disabled.example.com")
	assert.False(t, ok, "a disabled source's issuer must not be found")
}
