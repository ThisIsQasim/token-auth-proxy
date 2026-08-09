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
			cfg, err := Load(path)

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
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
}

func TestApplyDefaults_TimeoutsRetainOverrides(t *testing.T) {
	path := writeTempConfig(t, "target: http://localhost:9000\ntimeouts:\n  dial: 2s\n  read: 45s\n")
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Second, cfg.Timeouts.Dial)
	assert.Equal(t, 45*time.Second, cfg.Timeouts.Read)
	// Untouched fields still get defaulted.
	assert.Equal(t, defaultWriteTimeout, cfg.Timeouts.Write)
	assert.Equal(t, defaultIdleTimeout, cfg.Timeouts.Idle)
	assert.Equal(t, defaultReadHeaderTimeout, cfg.Timeouts.ReadHeader)
	assert.Equal(t, defaultResponseHeaderTimeout, cfg.Timeouts.ResponseHeader)
}

func TestApplyDefaults_AllTimeoutsDefaulted(t *testing.T) {
	path := writeTempConfig(t, "target: http://localhost:9000\n")
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, defaultReadHeaderTimeout, cfg.Timeouts.ReadHeader)
	assert.Equal(t, defaultReadTimeout, cfg.Timeouts.Read)
	assert.Equal(t, defaultWriteTimeout, cfg.Timeouts.Write)
	assert.Equal(t, defaultIdleTimeout, cfg.Timeouts.Idle)
	assert.Equal(t, defaultDialTimeout, cfg.Timeouts.Dial)
	assert.Equal(t, defaultResponseHeaderTimeout, cfg.Timeouts.ResponseHeader)
}
