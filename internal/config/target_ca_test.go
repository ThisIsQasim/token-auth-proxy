package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	priv, err := testSPRSAKey()
	require.NoError(t, err)
	return testSPCertPEM(t, priv)
}

func TestTargetCACert_Valid(t *testing.T) {
	caPEM := testCAPEM(t)

	for name, value := range map[string]string{
		"pem":    caPEM,
		"base64": base64.StdEncoding.EncodeToString([]byte(caPEM)),
	} {
		t.Run(name, func(t *testing.T) {
			c := &Config{ListenAddr: ":8080", Target: "https://opensearch.internal:9200", TargetCACert: value}
			require.NoError(t, c.Validate())
			require.NotNil(t, c.TargetCAPool())

			want, err := ParseCACertPool(caPEM)
			require.NoError(t, err)
			assert.True(t, c.TargetCAPool().Equal(want))
		})
	}
}

func TestTargetCACert_UnsetMeansSystemRoots(t *testing.T) {
	c := &Config{ListenAddr: ":8080", Target: "https://opensearch.internal:9200"}
	require.NoError(t, c.Validate())
	assert.Nil(t, c.TargetCAPool(), "no pool: the transport keeps the system roots")
}

func TestTargetCACert_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		target string
		cert   string
		errSub string
	}{
		{"not a certificate", "https://opensearch.internal:9200", "nope", "target_ca_cert"},
		{"truncated pem", "https://opensearch.internal:9200", "-----BEGIN CERTIFICATE-----\nMIIB", "target_ca_cert"},
		{"http target", "http://opensearch.internal:9200", testCAPEM(t), "only applies to an https target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{ListenAddr: ":8080", Target: tt.target, TargetCACert: tt.cert}
			assert.ErrorContains(t, c.Validate(), tt.errSub)
		})
	}
}

func TestTargetCACert_ValidateClearsAStalePool(t *testing.T) {
	c := &Config{ListenAddr: ":8080", Target: "https://opensearch.internal:9200", TargetCACert: testCAPEM(t)}
	require.NoError(t, c.Validate())
	require.NotNil(t, c.TargetCAPool())

	c.TargetCACert = ""
	require.NoError(t, c.Validate())
	assert.Nil(t, c.TargetCAPool())
}

func TestTargetCACert_FromFlagAndEnv(t *testing.T) {
	caPEM := testCAPEM(t)

	cfg, err := loadLayered("", newFlagSet(t, "--target", "https://opensearch.internal:9200", "--target-ca-cert", caPEM))
	require.NoError(t, err)
	assert.NotNil(t, cfg.TargetCAPool())

	t.Setenv("TAP_TARGET", "https://opensearch.internal:9200")
	t.Setenv("TAP_TARGET_CA_CERT", caPEM)
	cfg, err = loadLayered("", newFlagSet(t))
	require.NoError(t, err)
	assert.NotNil(t, cfg.TargetCAPool())
}

func TestTargetCACert_FromYAMLFileReference(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, []byte(testCAPEM(t)), 0o600))
	path := writeTempFile(t, "target: https://opensearch.internal:9200\ntarget_ca_cert: ${file:"+caPath+"}\n")

	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)
	assert.NotNil(t, cfg.TargetCAPool())
}

// The CA is read once with the transport, so a change to it is not a
// hot-reloadable change and the watcher asks for a restart instead.
func TestTargetCACert_NeedsARestart(t *testing.T) {
	prev := &Config{ListenAddr: ":8080", Target: "https://opensearch.internal:9200", TargetCACert: "one"}
	next := &Config{ListenAddr: ":8080", Target: "https://opensearch.internal:9200", TargetCACert: "two"}
	assert.False(t, hotReloadableFieldsChanged(prev, next), "only the CA differs")

	next.Target = "https://other.internal:9200"
	assert.True(t, hotReloadableFieldsChanged(prev, next), "a target change still hot-reloads")
}
