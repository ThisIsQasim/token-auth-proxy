package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
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

// validSAMLSessionKey is 32 bytes, satisfying minSessionSigningKeyLen.
const validSAMLSessionKey = "01234567890123456789012345678901"

// validSAMLSource returns a fresh, already-defaulted, valid SAMLSource
// whose SessionSigningKeyEnv is guaranteed set via t.Setenv.
func validSAMLSource(t *testing.T) SAMLSource {
	t.Helper()
	t.Setenv("SAML_TEST_SESSION_KEY", validSAMLSessionKey)
	s := SAMLSource{
		Name:                 "saml-a",
		Issuer:               "https://idp.example.com/metadata",
		IDPMetadataURL:       "https://idp.example.com/metadata",
		SPBaseURL:            "https://proxy.example.com",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/saml-a/acs",
		SessionCookie:        "saml_a_session",
		SessionSigningKeyEnv: "SAML_TEST_SESSION_KEY",
	}
	s.applyDefaults()
	return s
}

// testSPRSAKey is cached per process, same rationale as
// internal/authn's identical sharedRSAKey/sharedSAMLIDPKey pattern:
// real RSA keygen is slow enough to matter across many test cases.
var testSPRSAKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// testSPCertPEM returns a PEM-encoded, self-signed X.509 certificate
// for priv.
func testSPCertPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-sp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testSPKeyCertPEM returns a matching PEM-encoded RSA private key
// (PKCS#1) and self-signed certificate, for sp_key_env/sp_cert test
// cases.
func testSPKeyCertPEM(t *testing.T) (keyPEM, certPEM string) {
	t.Helper()
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	return keyPEM, testSPCertPEM(t, priv)
}

func TestJWTSource_Validate(t *testing.T) {
	caPriv, err := testSPRSAKey()
	require.NoError(t, err)
	caPEM := testSPCertPEM(t, caPriv)

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
			name:   "valid ca_cert on an https jwks_url",
			mutate: func(j *JWTSource) { j.CACert = caPEM },
		},
		{
			name: "valid ca_cert on an https oidc_discovery_url",
			mutate: func(j *JWTSource) {
				j.JWKSURL = ""
				j.OIDCDiscoveryURL = "https://issuer.example.com/.well-known/openid-configuration"
				j.CACert = caPEM
			},
		},
		{
			name:      "ca_cert that isn't a certificate",
			mutate:    func(j *JWTSource) { j.CACert = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n" },
			wantErr:   true,
			errSubstr: "ca_cert",
		},
		{
			name:      "ca_cert with no PEM block",
			mutate:    func(j *JWTSource) { j.CACert = "/etc/ssl/certs/ca.pem" },
			wantErr:   true,
			errSubstr: "no PEM-encoded certificate found",
		},
		{
			// A CA bundle on a plaintext endpoint is never consulted, so
			// the stated trust requirement would be silently unenforced.
			name: "ca_cert on an http jwks_url",
			mutate: func(j *JWTSource) {
				j.JWKSURL = "http://issuer.example.com/jwks.json"
				j.CACert = caPEM
			},
			wantErr:   true,
			errSubstr: "ca_cert is set but jwks_url is http://",
		},
		{
			name: "ca_cert on an http oidc_discovery_url",
			mutate: func(j *JWTSource) {
				j.JWKSURL = ""
				j.OIDCDiscoveryURL = "http://issuer.example.com/.well-known/openid-configuration"
				j.CACert = caPEM
			},
			wantErr:   true,
			errSubstr: "ca_cert is set but oidc_discovery_url is http://",
		},
		{
			// Without ca_cert, http stays permitted exactly as before —
			// integration tests and local dev depend on it.
			name:   "http jwks_url with no ca_cert is still allowed",
			mutate: func(j *JWTSource) { j.JWKSURL = "http://issuer.example.com/jwks.json" },
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
			name: "missing sp_base_url", mutate: func(s *SAMLSource) { s.SPBaseURL = "" },
			wantErr: true, errSubstr: "sp_base_url is required",
		},
		{
			name: "relative sp_base_url", mutate: func(s *SAMLSource) { s.SPBaseURL = "/proxy" },
			wantErr: true, errSubstr: "sp_base_url",
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
			name: "acs_path without leading slash", mutate: func(s *SAMLSource) { s.ACSPath = "saml/acs" },
			wantErr: true, errSubstr: "must begin with",
		},
		{
			name: "acs_path is /healthz", mutate: func(s *SAMLSource) { s.ACSPath = "/healthz" },
			wantErr: true, errSubstr: "/healthz",
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
		{
			name: "session_signing_key_env value too short",
			mutate: func(s *SAMLSource) {
				t.Setenv("SAML_TEST_SESSION_KEY_SHORT", "too-short")
				s.SessionSigningKeyEnv = "SAML_TEST_SESSION_KEY_SHORT"
			},
			wantErr: true, errSubstr: "must be at least 32 bytes",
		},
		{
			name: "sp_key_env without sp_cert",
			mutate: func(s *SAMLSource) {
				s.SPKeyEnv = "SAML_TEST_SP_KEY"
			},
			wantErr: true, errSubstr: "must be set together",
		},
		{
			name: "sp_cert without sp_key_env",
			mutate: func(s *SAMLSource) {
				_, certPEM := testSPKeyCertPEM(t)
				s.SPCert = certPEM
			},
			wantErr: true, errSubstr: "must be set together",
		},
		{
			name: "sp_key_env names an unset env var",
			mutate: func(s *SAMLSource) {
				_, certPEM := testSPKeyCertPEM(t)
				s.SPKeyEnv = "SAML_TEST_SP_KEY_NOT_SET"
				s.SPCert = certPEM
			},
			wantErr: true, errSubstr: "is not set",
		},
		{
			name: "sp_key_env value is not valid PEM",
			mutate: func(s *SAMLSource) {
				_, certPEM := testSPKeyCertPEM(t)
				t.Setenv("SAML_TEST_SP_KEY_MALFORMED", "not a pem key")
				s.SPKeyEnv = "SAML_TEST_SP_KEY_MALFORMED"
				s.SPCert = certPEM
			},
			wantErr: true, errSubstr: "sp_key_env",
		},
		{
			name: "sp_cert is not valid PEM",
			mutate: func(s *SAMLSource) {
				keyPEM, _ := testSPKeyCertPEM(t)
				t.Setenv("SAML_TEST_SP_KEY_VALID", keyPEM)
				s.SPKeyEnv = "SAML_TEST_SP_KEY_VALID"
				s.SPCert = "not a pem cert"
			},
			wantErr: true, errSubstr: "sp_cert",
		},
		{
			name: "sp_cert public key does not match sp_key_env",
			mutate: func(s *SAMLSource) {
				keyPEM, _ := testSPKeyCertPEM(t)
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				t.Setenv("SAML_TEST_SP_KEY_MISMATCH", keyPEM)
				s.SPKeyEnv = "SAML_TEST_SP_KEY_MISMATCH"
				s.SPCert = testSPCertPEM(t, other)
			},
			wantErr: true, errSubstr: "does not match",
		},
		{
			name: "valid sp_key_env/sp_cert pair",
			mutate: func(s *SAMLSource) {
				keyPEM, certPEM := testSPKeyCertPEM(t)
				t.Setenv("SAML_TEST_SP_KEY_OK", keyPEM)
				s.SPKeyEnv = "SAML_TEST_SP_KEY_OK"
				s.SPCert = certPEM
			},
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

	t.Run("jwt credentials cookie collides with saml session_cookie", func(t *testing.T) {
		jwt := validJWTSource()
		saml := validSAMLSource(t)
		jwt.Credentials = []CredentialLocation{{Location: "cookie", Name: saml.SessionCookie}}

		a := InboundAuthConfig{JWT: []JWTSource{jwt}, SAML: &saml}
		assert.ErrorContains(t, a.Validate(), "collides with inbound.auth.saml.session_cookie")
	})

	t.Run("jwt cookie credential with a different name than session_cookie is fine", func(t *testing.T) {
		jwt := validJWTSource()
		saml := validSAMLSource(t)
		jwt.Credentials = []CredentialLocation{{Location: "cookie", Name: "not_" + saml.SessionCookie}}

		a := InboundAuthConfig{JWT: []JWTSource{jwt}, SAML: &saml}
		assert.NoError(t, a.Validate())
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

// TestInboundAuthConfig_JWTEnabled is the regression guard for JWT
// verification enforcement being scoped strictly to JWT sources: a
// SAML-only config must report Enabled()==true (something is
// configured) but JWTEnabled()==false (nothing here should ever cause
// the JWT middleware to start rejecting requests), since SAML
// verification isn't implemented.
func TestInboundAuthConfig_JWTEnabled(t *testing.T) {
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
			name: "all jwt sources disabled",
			a:    InboundAuthConfig{JWT: []JWTSource{{Name: "j", Disabled: true}}},
			want: false,
		},
		{
			name: "SAML-only, enabled: Enabled() true but JWTEnabled() must stay false",
			a:    InboundAuthConfig{SAML: &SAMLSource{Name: "s"}},
			want: false,
		},
		{
			name: "SAML enabled and a disabled jwt source",
			a: InboundAuthConfig{
				JWT:  []JWTSource{{Name: "j", Disabled: true}},
				SAML: &SAMLSource{Name: "s"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.JWTEnabled())
		})
	}

	t.Run("SAML-only config: Enabled true, JWTEnabled false", func(t *testing.T) {
		a := InboundAuthConfig{SAML: &SAMLSource{Name: "s"}}
		assert.True(t, a.Enabled(), "a configured, non-disabled SAML source makes Enabled true")
		assert.False(t, a.JWTEnabled(), "but must never make JWTEnabled true")
	})
}

func TestInboundAuthConfig_SAMLEnabled(t *testing.T) {
	tests := []struct {
		name string
		a    InboundAuthConfig
		want bool
	}{
		{name: "no saml source", a: InboundAuthConfig{}, want: false},
		{name: "saml source configured, not disabled", a: InboundAuthConfig{SAML: &SAMLSource{Name: "s"}}, want: true},
		{
			name: "saml source configured but disabled",
			a:    InboundAuthConfig{SAML: &SAMLSource{Name: "s", Disabled: true}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.SAMLEnabled())
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

	t.Run("zero idp_metadata_cache_ttl gets defaulted", func(t *testing.T) {
		var s SAMLSource
		s.applyDefaults()
		assert.Equal(t, defaultIDPMetadataCacheTTL, s.IDPMetadataCacheTTL)
	})

	t.Run("explicit idp_metadata_cache_ttl survives", func(t *testing.T) {
		s := SAMLSource{IDPMetadataCacheTTL: 15 * time.Minute}
		s.applyDefaults()
		assert.Equal(t, 15*time.Minute, s.IDPMetadataCacheTTL)
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

// testBasicHash is cached per process for the same reason testSPRSAKey
// is: bcrypt at a realistic cost is deliberately slow, and every basic
// test case wants a valid hash. MinCost keeps the tests fast — the cost
// factor is the operator's choice, and nothing under test depends on it.
var testBasicHash = sync.OnceValues(func() (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	return string(h), err
})

// validBasicSource returns a fresh, already-defaulted, valid
// BasicSource, so each test only needs to mutate the field it cares
// about.
func validBasicSource(t *testing.T) BasicSource {
	t.Helper()
	hash, err := testBasicHash()
	require.NoError(t, err)
	b := BasicSource{Users: []BasicUser{{Username: "alice", PasswordHash: hash}}}
	b.applyDefaults()
	return b
}

func TestBasicSource_ApplyDefaults(t *testing.T) {
	var b BasicSource
	b.applyDefaults()
	assert.Equal(t, defaultBasicRealm, b.Realm)

	b = BasicSource{Realm: "internal tools"}
	b.applyDefaults()
	assert.Equal(t, "internal tools", b.Realm)
}

func TestBasicSource_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(b *BasicSource)
		wantErr   bool
		errSubstr string
	}{
		{name: "valid"},
		{
			name:      "no users",
			mutate:    func(b *BasicSource) { b.Users = nil },
			wantErr:   true,
			errSubstr: "at least one user",
		},
		{
			name:      "empty username",
			mutate:    func(b *BasicSource) { b.Users[0].Username = "" },
			wantErr:   true,
			errSubstr: "username is required",
		},
		{
			name: "duplicate username",
			mutate: func(b *BasicSource) {
				b.Users = append(b.Users, b.Users[0])
			},
			wantErr:   true,
			errSubstr: "already used by another user",
		},
		{
			name:      "missing password hash",
			mutate:    func(b *BasicSource) { b.Users[0].PasswordHash = "" },
			wantErr:   true,
			errSubstr: "password_hash is required",
		},
		{
			name:      "plaintext password rejected",
			mutate:    func(b *BasicSource) { b.Users[0].PasswordHash = "hunter2" },
			wantErr:   true,
			errSubstr: "not a bcrypt hash",
		},
		{
			name:      "truncated hash rejected",
			mutate:    func(b *BasicSource) { b.Users[0].PasswordHash = "$2y$12$tooshort" },
			wantErr:   true,
			errSubstr: "not a bcrypt hash",
		},
		{
			name:      "realm with a quote rejected",
			mutate:    func(b *BasicSource) { b.Realm = `say "hi"` },
			wantErr:   true,
			errSubstr: "quote or backslash",
		},
		{
			name:      "realm with a newline rejected",
			mutate:    func(b *BasicSource) { b.Realm = "one\ntwo" },
			wantErr:   true,
			errSubstr: "control characters",
		},
		{
			name:      "empty realm rejected",
			mutate:    func(b *BasicSource) { b.Realm = "" },
			wantErr:   true,
			errSubstr: "must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validBasicSource(t)
			if tt.mutate != nil {
				tt.mutate(&b)
			}

			err := b.validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.errSubstr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestInboundAuthConfig_BasicEnabled(t *testing.T) {
	b := validBasicSource(t)

	var none InboundAuthConfig
	assert.False(t, none.BasicEnabled())
	assert.False(t, none.Enabled())

	live := InboundAuthConfig{Basic: &b}
	assert.True(t, live.BasicEnabled())
	assert.True(t, live.Enabled())
	assert.False(t, live.JWTEnabled())
	assert.False(t, live.SAMLEnabled())

	disabled := b
	disabled.Disabled = true
	staged := InboundAuthConfig{Basic: &disabled}
	assert.False(t, staged.BasicEnabled())
	assert.False(t, staged.Enabled())
}

func TestInboundAuthConfig_Validate_BasicCollidesWithPrefixlessJWTHeader(t *testing.T) {
	b := validBasicSource(t)
	j := validJWTSource()
	j.Credentials = []CredentialLocation{{Location: "header", Name: "Authorization"}}

	a := InboundAuthConfig{JWT: []JWTSource{j}, Basic: &b}
	err := a.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "collides with inbound.auth.basic")

	// The default "Bearer " prefix tells the two schemes apart, so the
	// same pair is fine.
	j.Credentials = []CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}}
	a = InboundAuthConfig{JWT: []JWTSource{j}, Basic: &b}
	require.NoError(t, a.Validate())

	// A disabled basic source can't collide with anything.
	disabled := b
	disabled.Disabled = true
	j.Credentials = []CredentialLocation{{Location: "header", Name: "Authorization"}}
	a = InboundAuthConfig{JWT: []JWTSource{j}, Basic: &disabled}
	require.NoError(t, a.Validate())
}
