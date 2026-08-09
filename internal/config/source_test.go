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
