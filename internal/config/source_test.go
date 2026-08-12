package config

import (
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

const jwtSourceJSON = `[{"name":"jwt-a","issuer":"https://issuer.example.com","jwks_url":"https://issuer.example.com/jwks.json","credentials":[{"location":"header","name":"Authorization","prefix":"Bearer "},{"location":"cookie","name":"session"}]}]`

func TestResolve_JSONFieldOverride_EnvOnly_NoFile(t *testing.T) {
	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", jwtSourceJSON)

	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)

	require.Len(t, src.Config.Inbound.Auth.JWT, 1)
	j := src.Config.Inbound.Auth.JWT[0]
	assert.Equal(t, "jwt-a", j.Name)
	assert.Equal(t, "https://issuer.example.com", j.Issuer)
	require.Len(t, j.Credentials, 2)
	assert.Equal(t, CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "}, j.Credentials[0])
	assert.Equal(t, CredentialLocation{Location: "cookie", Name: "session"}, j.Credentials[1])
}

func TestLoadLayered_JSONFieldOverride_FlagWinsOverEnv(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `[{"name":"from-env","issuer":"https://env.example.com","jwks_url":"https://env.example.com/jwks.json"}]`)

	fs := newFlagSet(t, "--inbound-auth-jwt-json", `[{"name":"from-flag","issuer":"https://flag.example.com","jwks_url":"https://flag.example.com/jwks.json"}]`)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1)
	assert.Equal(t, "from-flag", cfg.Inbound.Auth.JWT[0].Name, "flag must win over env")
}

func TestLoadLayered_JSONFieldOverride_EnvWinsOverFile_FullReplace(t *testing.T) {
	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    jwt:
      - name: from-file
        issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `[{"name":"from-env","issuer":"https://env.example.com","jwks_url":"https://env.example.com/jwks.json"}]`)

	fs := newFlagSet(t)
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1, "the env override must fully replace the file's list, not merge into it")
	assert.Equal(t, "from-env", cfg.Inbound.Auth.JWT[0].Name)
}

func TestLoadLayered_JSONFieldOverride_AbsentLeavesFileUntouched(t *testing.T) {
	path := writeTempFile(t, `
target: http://from-file:9000
inbound:
  auth:
    jwt:
      - name: from-file
        issuer: https://file.example.com
        jwks_url: https://file.example.com/jwks.json
`)
	fs := newFlagSet(t) // no flag, no env
	cfg, err := loadLayered(path, fs)
	require.NoError(t, err)

	require.Len(t, cfg.Inbound.Auth.JWT, 1)
	assert.Equal(t, "from-file", cfg.Inbound.Auth.JWT[0].Name)
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
	t.Setenv("TAP_INBOUND_AUTH_JWT_JSON", `{"name":"jwt-a"}`)

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err, "a well-formed but wrongly-shaped JSON value must still fail, not be silently accepted")
}

func TestResolve_SAMLJSONFieldOverride_Object(t *testing.T) {
	t.Setenv("TAP_TARGET", "http://static:9000")
	t.Setenv("TAP_SAML_TEST_SESSION_KEY", "secret")
	t.Setenv("TAP_INBOUND_AUTH_SAML_JSON", `{"name":"saml-a","issuer":"https://idp.example.com/metadata","idp_metadata_url":"https://idp.example.com/metadata","sp_entity_id":"https://proxy.example.com/saml/metadata","acs_path":"/saml/saml-a/acs","session_cookie":"saml_a_session","session_signing_key_env":"TAP_SAML_TEST_SESSION_KEY"}`)

	fs := newFlagSet(t)
	src, err := Resolve(fs)
	require.NoError(t, err)
	require.NotNil(t, src.Config)

	require.NotNil(t, src.Config.Inbound.Auth.SAML)
	assert.Equal(t, "saml-a", src.Config.Inbound.Auth.SAML.Name)
	assert.Equal(t, "https://idp.example.com/metadata", src.Config.Inbound.Auth.SAML.Issuer)
	assert.Equal(t, "/saml/saml-a/acs", src.Config.Inbound.Auth.SAML.ACSPath)
}

func TestLoadLayered_SAMLJSONFieldOverride_WrongShapeStillErrors(t *testing.T) {
	path := writeTempFile(t, "target: http://from-file:9000\n")
	// A JSON array, not an object — valid JSON, wrong shape for a
	// single optional source.
	t.Setenv("TAP_INBOUND_AUTH_SAML_JSON", `[{"name":"saml-a"}]`)

	fs := newFlagSet(t)
	_, err := loadLayered(path, fs)
	require.Error(t, err, "a well-formed but wrongly-shaped JSON value must still fail, not be silently accepted")
}
