package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvKey(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		value   string
		wantKey string
	}{
		{name: "target", envVar: "TAP_TARGET", value: "http://x:1", wantKey: "target"},
		{name: "listen_addr", envVar: "TAP_LISTEN_ADDR", value: ":9090", wantKey: "listen_addr"},
		{name: "config", envVar: "TAP_CONFIG", value: "/etc/x.yaml", wantKey: "config"},
		{name: "nested timeout", envVar: "TAP_TIMEOUT_DIAL", value: "5s", wantKey: "timeouts.dial"},
		{name: "unrecognized TAP_ var", envVar: "TAP_NONSENSE", value: "x", wantKey: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, val := envKey(tt.envVar, tt.value)
			assert.Equal(t, tt.wantKey, key)
			if tt.wantKey != "" {
				assert.Equal(t, tt.value, val)
			}
		})
	}
}

func newFlagSet(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	require.NoError(t, fs.Parse(args))
	return fs
}

func writeTempFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeAtomic(t, path, contents)
	return path
}

func TestLoadLayered_FileOnly(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)
	assert.Equal(t, "http://from-file:9000", cfg.Target)
	assert.Equal(t, ":8080", cfg.ListenAddr, "default applied when unset anywhere")
}

func TestLoadLayered_EnvOverridesFile(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_TARGET", "http://from-env:9000")

	fs := newFlagSet(t) // no flags passed
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)
	assert.Equal(t, "http://from-env:9000", cfg.Target, "env should win over file")
}

func TestLoadLayered_FlagOverridesEnvAndFile(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_TARGET", "http://from-env:9000")

	fs := newFlagSet(t, "--target", "http://from-flag:9000")
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)
	assert.Equal(t, "http://from-flag:9000", cfg.Target, "flag should win over both env and file")
}

func TestLoadLayered_DurationOverride(t *testing.T) {
	path := writeTempFile(t, "target: http://x:9000\ntimeouts:\n  dial: 1s\n")

	t.Run("env duration", func(t *testing.T) {
		t.Setenv("TAP_TIMEOUT_DIAL", "9s")
		fs := newFlagSet(t)
		cfg, err := loadLayered(path, fs)
		require.NoError(t, err)
		assert.Equal(t, 9*time.Second, cfg.Timeouts.Dial)
	})

	t.Run("flag duration wins over env", func(t *testing.T) {
		t.Setenv("TAP_TIMEOUT_DIAL", "9s")
		fs := newFlagSet(t, "--timeout-dial", "13s")
		cfg, err := loadLayered(path, fs)
		require.NoError(t, err)
		assert.Equal(t, 13*time.Second, cfg.Timeouts.Dial)
	})
}

func TestLoadLayered_MalformedEnvDuration(t *testing.T) {
	path := writeTempFile(t, "target: http://x:9000\n")
	t.Setenv("TAP_TIMEOUT_DIAL", "not-a-duration")

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err, "a malformed env duration must fail fast, not silently fall back")
}

func TestLoadLayered_StaticNoFile(t *testing.T) {
	fs := newFlagSet(t, "--target", "http://static:9000", "--listen-addr", ":7000")
	cfg, err := loadLayered("", fs)
	require.NoError(t, err)
	assert.Equal(t, "http://static:9000", cfg.Target)
	assert.Equal(t, ":7000", cfg.ListenAddr)
}

func TestResolve_ConfigPathViaFlag(t *testing.T) {
	fs := newFlagSet(t, "--config", "/etc/token-auth-proxy/config.yaml")
	src, err := Resolve(fs)
	require.NoError(t, err)
	assert.Equal(t, "/etc/token-auth-proxy/config.yaml", src.ConfigPath)
	assert.Nil(t, src.Config)
}

func TestResolve_ConfigPathViaEnv(t *testing.T) {
	t.Setenv("TAP_CONFIG", "/etc/token-auth-proxy/config.yaml")
	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	assert.Equal(t, "/etc/token-auth-proxy/config.yaml", src.ConfigPath)
}

func TestResolve_FlagConfigPathWinsOverEnv(t *testing.T) {
	t.Setenv("TAP_CONFIG", "/from-env.yaml")
	fs := newFlagSet(t, "--config", "/from-flag.yaml")
	src, err := Resolve(fs)
	require.NoError(t, err)
	assert.Equal(t, "/from-flag.yaml", src.ConfigPath)
}

func TestResolve_StaticFromFlags(t *testing.T) {
	fs := newFlagSet(t, "--target", "http://static:9000")
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)
	assert.Empty(t, src.ConfigPath)
	assert.Equal(t, "http://static:9000", src.Config.Target)
}

func TestResolve_NeitherConfigNorTargetErrors(t *testing.T) {
	fs := newFlagSet(t)
	_, err := Resolve(fs)
	require.Error(t, err)
}

const jwtSourceJSON = `[{"issuer":"https://issuer.example.com","jwks_url":"https://issuer.example.com/jwks.json","credentials":[{"location":"header","name":"Authorization","prefix":"Bearer "},{"location":"cookie","name":"session"}]}]`

func TestResolve_JSONFieldOverride_EnvOnly_NoFile(t *testing.T) {
	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", jwtSourceJSON)

	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)

	require.Len(t, src.Config.Inbound.Auth.JWT, 1)
	j := src.Config.Inbound.Auth.JWT[0]
	assert.Equal(t, "https://issuer.example.com", j.Issuer)
	require.Len(t, j.Credentials, 2)
	assert.Equal(t, CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "}, j.Credentials[0])
	assert.Equal(t, CredentialLocation{Location: "cookie", Name: "session"}, j.Credentials[1])
}

func TestLoadLayered_JSONFieldOverride_FlagWinsOverEnv(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `[{"issuer":"https://env.example.com","jwks_url":"https://env.example.com/jwks.json"}]`)

	fs := newFlagSet(t, "--inbound-auth-jwt-json", `[{"issuer":"https://flag.example.com","jwks_url":"https://flag.example.com/jwks.json"}]`)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1)
	assert.Equal(t, "https://flag.example.com", cfg.Inbound.Auth.JWT[0].Issuer, "flag must win over env")
}

func TestLoadLayered_JSONFieldOverride_EnvWinsOverFile_FullReplace(t *testing.T) {
	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    jwt:
      - issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `[{"issuer":"https://env.example.com","jwks_url":"https://env.example.com/jwks.json"}]`)

	fs := newFlagSet(t)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1, "the env override must fully replace the file's list, not merge into it")
	assert.Equal(t, "https://env.example.com", cfg.Inbound.Auth.JWT[0].Issuer)
}

func TestLoadLayered_JSONFieldOverride_AbsentLeavesFileUntouched(t *testing.T) {
	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    jwt:
      - issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)
	fs := newFlagSet(t) // no flag, no env
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1)
	assert.Equal(t, "https://file.example.com", cfg.Inbound.Auth.JWT[0].Issuer)
}

// TestLoadLayered_JSONFieldOverride_EmptyStringLeavesFileUntouched is a
// regression test for a real bug found in review: os.LookupEnv's ok is
// true for TAP_INBOUND_AUTH_JWT_JSON="" (a real-world artifact of
// container-env templating that conditionally renders an empty value
// rather than omitting the var entirely), so treating "set" as "any ok
// from LookupEnv" — rather than "set to a non-empty value" — made an
// empty override string flow into json.Unmarshal("") and fail the
// entire config load with a confusing "invalid JSON: unexpected end of
// JSON input", even though the operator's intent was clearly "no
// override".
func TestLoadLayered_JSONFieldOverride_EmptyStringLeavesFileUntouched(t *testing.T) {
	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    jwt:
      - issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", "")

	fs := newFlagSet(t)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1)
	assert.Equal(t, "https://file.example.com", cfg.Inbound.Auth.JWT[0].Issuer)
}

// TestLoadLayered_JSONFieldOverride_AtPrefixIsLiteral confirms the
// override only ever accepts inline JSON: a leading "@" is not treated
// as a file-path marker, so a value like "@/some/path" must fail as
// invalid JSON, not be interpreted as "read this file".
func TestLoadLayered_JSONFieldOverride_AtPrefixIsLiteral(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", "@/etc/token-auth-proxy/jwt-sources.json")

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid JSON")
}

func TestLoadLayered_JSONFieldOverride_MalformedJSON(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_INBOUND_AUTH_SAML_JSON", "not valid json")

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "inbound.auth.saml")
	assert.ErrorContains(t, err, "invalid JSON")
}

func TestLoadLayered_JSONFieldOverride_WrongShapeStillErrors(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	// A JSON object, not an array — valid JSON, wrong shape for a list.
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `{"issuer":"https://issuer.example.com"}`)

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err, "a well-formed but wrongly-shaped JSON value must still fail, not be silently accepted")
}

func TestResolve_SAMLJSONFieldOverride_Object(t *testing.T) {
	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_SAML_TEST_SESSION_KEY", validSAMLSessionKey)
	t.Setenv("TAP_INBOUND_AUTH_SAML_JSON", `{"issuer":"https://idp.example.com/metadata","idp_metadata_url":"https://idp.example.com/metadata","sp_base_url":"https://proxy.example.com","sp_entity_id":"https://proxy.example.com/saml/metadata","acs_path":"/saml/acs","session_cookie":"saml_session","session_signing_key_env":"TAP_SAML_TEST_SESSION_KEY"}`)

	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)

	require.NotNil(t, src.Config.Inbound.Auth.SAML)
	assert.Equal(t, "https://idp.example.com/metadata", src.Config.Inbound.Auth.SAML.Issuer)
	assert.Equal(t, "/saml/acs", src.Config.Inbound.Auth.SAML.ACSPath)
}

func TestLoadLayered_SAMLJSONFieldOverride_WrongShapeStillErrors(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	// A JSON array, not an object — valid JSON, wrong shape for a
	// single optional source.
	t.Setenv("TAP_INBOUND_AUTH_SAML_JSON", `[{"issuer":"https://idp.example.com/metadata"}]`)

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err, "a well-formed but wrongly-shaped JSON value must still fail, not be silently accepted")
}

func TestLoadLayered_BasicJSONFieldOverride_EnvAndFlag(t *testing.T) {
	hash, err := testBasicHash()
	require.NoError(t, err)

	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    basic:
      realm: from-file
      users:
        - username: from-file
          password_hash: `+hash+`
`)

	t.Setenv("TAP_INBOUND_AUTH_BASIC_JSON",
		`{"realm":"from-env","users":[{"username":"from-env","password_hash":"`+hash+`"}]}`)

	fs := newFlagSet(t)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)
	require.NotNil(t, cfg.Inbound.Auth.Basic)
	assert.Equal(t, "from-env", cfg.Inbound.Auth.Basic.Realm)
	require.Len(t, cfg.Inbound.Auth.Basic.Users, 1, "the override must fully replace the file's source, not merge into it")
	assert.Equal(t, "from-env", cfg.Inbound.Auth.Basic.Users[0].Username)

	fs = newFlagSet(t, "--inbound-auth-basic-json",
		`{"realm":"from-flag","users":[{"username":"from-flag","password_hash":"`+hash+`"}]}`)
	cfg, err = loadLayered(path, fs)
	require.NoError(t, err)
	require.NotNil(t, cfg.Inbound.Auth.Basic)
	assert.Equal(t, "from-flag", cfg.Inbound.Auth.Basic.Realm, "flag must win over env")
}

func TestResolve_BasicJSONFieldOverride_NoFile(t *testing.T) {
	hash, err := testBasicHash()
	require.NoError(t, err)

	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_INBOUND_AUTH_BASIC_JSON",
		`{"users":[{"username":"alice","password_hash":"`+hash+`"}]}`)

	src, err := Resolve(newFlagSet(t))
	require.NoError(t, err)
	require.NotNil(t, src.Config)
	require.NotNil(t, src.Config.Inbound.Auth.Basic)
	assert.True(t, src.Config.Inbound.Auth.BasicEnabled())
	assert.Equal(t, defaultBasicRealm, src.Config.Inbound.Auth.Basic.Realm, "defaults still apply to a JSON-provided source")
	assert.Equal(t, "alice", src.Config.Inbound.Auth.Basic.Users[0].Username)
}

// ca_cert carries multi-line PEM, which JSON escapes as \n — worth its
// own case, since it's the only field in a JWT source where the JSON
// and YAML spellings of the same value look nothing alike.
func TestResolve_JSONFieldOverride_CACert(t *testing.T) {
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	caPEM := testSPCertPEM(t, priv)

	jsonPEM, err := json.Marshal(caPEM)
	require.NoError(t, err)

	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", fmt.Sprintf(
		`[{"issuer":"https://issuer.example.com","jwks_url":"https://issuer.example.com/jwks.json","ca_cert":%s}]`,
		jsonPEM))

	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)

	require.Len(t, src.Config.Inbound.Auth.JWT, 1)
	assert.Equal(t, caPEM, src.Config.Inbound.Auth.JWT[0].CACert)
}
