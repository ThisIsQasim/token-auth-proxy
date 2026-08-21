package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBcryptHash is a real bcrypt hash, present here for one reason: it is
// the value most likely to be broken by an escaping rule, since it contains
// three '$' characters. Every test using it asserts it survives untouched.
const testBcryptHash = "$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.hK8." // #nosec G101 -- a bcrypt hash of a throwaway test password, not a credential

func writeSecretFile(t *testing.T, dir, name, contents string) {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

}

func TestInterpolateString(t *testing.T) {
	dir := t.TempDir()
	writeSecretFile(t, dir, "secret", "s3cr3t\n")
	writeSecretFile(t, dir, "crlf", "s3cr3t\r\n")
	writeSecretFile(t, dir, "trailing-space", "s3cr3t \n")
	writeSecretFile(t, dir, "no-newline", "s3cr3t")
	writeSecretFile(t, dir, "indirect", "${file:secret}")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "adir"), 0o750))

	t.Setenv("TAP_TEST_INTERP_VALUE", "from-env")
	t.Setenv("TAP_TEST_INTERP_EMPTY", "")
	t.Setenv("TAP_TEST_INTERP_INDIRECT", "${file:secret}")

	tests := []struct {
		name      string
		in        string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{name: "no reference at all", in: "http://localhost:9000", want: "http://localhost:9000"},
		{name: "env reference", in: "${env:TAP_TEST_INTERP_VALUE}", want: "from-env"},
		{name: "env reference embedded mid-string", in: "https://${env:TAP_TEST_INTERP_VALUE}/metadata", want: "https://from-env/metadata"},
		{name: "multiple references in one string", in: "${env:TAP_TEST_INTERP_VALUE}-${env:TAP_TEST_INTERP_VALUE}", want: "from-env-from-env"},
		{name: "env set but empty resolves to empty", in: "[${env:TAP_TEST_INTERP_EMPTY}]", want: "[]"},
		{name: "file reference strips one trailing newline", in: "${file:secret}", want: "s3cr3t"},
		{name: "file reference strips one trailing crlf", in: "${file:crlf}", want: "s3cr3t"},
		{name: "file reference keeps a meaningful trailing space", in: "${file:trailing-space}", want: "s3cr3t "},
		{name: "file reference without a trailing newline", in: "${file:no-newline}", want: "s3cr3t"},
		{name: "absolute file reference", in: "${file:" + filepath.Join(dir, "secret") + "}", want: "s3cr3t"},

		// The whole reason '$' is only special before '{'.
		{name: "bcrypt hash passes through untouched", in: testBcryptHash, want: testBcryptHash},
		{name: "bare dollar is not special", in: "cost is $5 or $$5", want: "cost is $5 or $$5"},
		{name: "escaped reference", in: "$${env:TAP_TEST_INTERP_VALUE}", want: "${env:TAP_TEST_INTERP_VALUE}"},
		{name: "escaped reference mid-string", in: "a $${file:x} b", want: "a ${file:x} b"},
		{name: "shell-style braces pass through", in: "${HOME}/x", want: "${HOME}/x"},
		{name: "non-type prefix passes through", in: "${C:\\secrets}", want: "${C:\\secrets}"},
		{name: "empty braces pass through", in: "${}", want: "${}"},

		// A resolved value is never re-scanned.
		{name: "env value holding a reference is not re-scanned", in: "${env:TAP_TEST_INTERP_INDIRECT}", want: "${file:secret}"},
		{name: "file contents holding a reference are not re-scanned", in: "${file:indirect}", want: "${file:secret}"},

		{name: "unknown reference type", in: "${vault:secret/db}", wantErr: true, errSubstr: `unknown reference type "vault"`},
		{name: "unterminated reference", in: "${env:X", wantErr: true, errSubstr: "unterminated"},
		{name: "unset env var", in: "${env:TAP_TEST_INTERP_MISSING}", wantErr: true, errSubstr: "environment variable is not set"},
		{name: "empty env var name", in: "${env:}", wantErr: true, errSubstr: "name is empty"},
		{name: "missing file", in: "${file:nope}", wantErr: true, errSubstr: "nope"},
		{name: "directory reference", in: "${file:adir}", wantErr: true, errSubstr: "is a directory"},
		{name: "empty file path", in: "${file:}", wantErr: true, errSubstr: "path is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := interpolateString(tt.in, dir)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errSubstr != "" {
					assert.ErrorContains(t, err, tt.errSubstr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInterpolateString_FileSizeCap(t *testing.T) {
	dir := t.TempDir()
	writeSecretFile(t, dir, "huge", strings.Repeat("x", maxReferencedFileSize+1))

	_, err := interpolateString("${file:huge}", dir)
	require.Error(t, err)
	assert.ErrorContains(t, err, "over the")
}

func TestInterpolateValue_WalksNestedStructures(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TAP_TEST_INTERP_VALUE", "from-env")

	in := map[string]any{
		"scalar": "${env:TAP_TEST_INTERP_VALUE}",
		"number": 42,
		"bool":   true,
		"list": []any{
			"${env:TAP_TEST_INTERP_VALUE}",
			map[string]any{"nested": "${env:TAP_TEST_INTERP_VALUE}"},
		},
		// yaml.v3 hands back map[any]any for any mapping with a non-string
		// key; koanf only normalizes that later, so the walker has to
		// descend into it here or the reference would silently survive.
		"weird": map[any]any{true: "${env:TAP_TEST_INTERP_VALUE}"},
	}

	out, err := interpolateValue(in, dir, "")
	require.NoError(t, err)

	m, ok := out.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "from-env", m["scalar"])
	assert.Equal(t, 42, m["number"])
	assert.Equal(t, true, m["bool"])

	list, ok := m["list"].([]any)
	require.True(t, ok)
	assert.Equal(t, "from-env", list[0])
	assert.Equal(t, map[string]any{"nested": "from-env"}, list[1])

	weird, ok := m["weird"].(map[any]any)
	require.True(t, ok)
	assert.Equal(t, "from-env", weird[true])
}

func TestInterpolateValue_ErrorNamesTheKeyPath(t *testing.T) {
	in := map[string]any{
		"inbound": map[string]any{
			"auth": map[string]any{
				"basic": map[string]any{
					"users": []any{
						map[string]any{"password_hash": "${env:TAP_TEST_INTERP_MISSING}"},
					},
				},
			},
		},
	}

	_, err := interpolateValue(in, t.TempDir(), "")
	require.Error(t, err)
	assert.ErrorContains(t, err, "inbound.auth.basic.users[0].password_hash")
}

func TestLoadLayered_InterpolatesFileValues(t *testing.T) {
	dir := t.TempDir()
	writeSecretFile(t, dir, "target", "http://localhost:9000\n")
	t.Setenv("TAP_TEST_INTERP_ADDR", ":9090")
	t.Setenv("TAP_TEST_INTERP_DIAL", "2s")

	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"listen_addr: \"${env:TAP_TEST_INTERP_ADDR}\"\n"+
			"target: \"${file:target}\"\n"+
			"timeouts:\n  dial: \"${env:TAP_TEST_INTERP_DIAL}\"\n"), 0o600))

	cfg, err := loadLayered(path, nil)
	require.NoError(t, err)
	assert.Equal(t, ":9090", cfg.ListenAddr)
	assert.Equal(t, "http://localhost:9000", cfg.Target)
	// A reference feeding a non-string field still decodes: koanf
	// unmarshals with WeaklyTypedInput plus a duration hook.
	assert.Equal(t, 2*time.Second, cfg.Timeouts.Dial)
}

func TestLoadLayered_InterpolationFailureIsAConfigError(t *testing.T) {
	path := writeTempConfig(t, "target: \"${env:TAP_TEST_INTERP_DEFINITELY_MISSING}\"\n")

	_, err := loadLayered(path, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "environment variable is not set")
	assert.ErrorContains(t, err, "target")
}

func TestInterpolatingProvider_ReadBytesUnsupported(t *testing.T) {
	_, err := newInterpolatingProvider("config.yaml").ReadBytes()
	require.Error(t, err)
}
