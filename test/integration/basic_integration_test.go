//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

// basicHash is generated once per process: bcrypt is deliberately slow,
// and every case here wants the same valid hash. MinCost keeps it out of
// the test's runtime — nothing here depends on the cost factor.
var basicHash = sync.OnceValues(func() (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	return string(h), err
})

func basicHeader(username, password string) http.Header {
	credential := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return http.Header{"Authorization": []string{"Basic " + credential}}
}

// basicConfigYAML renders a whole config file with a basic source whose
// single user's password_hash is written as passwordHashField — a
// literal hash in most cases, a ${...} reference in the interpolation
// tests.
func basicConfigYAML(target, username, passwordHashField string) string {
	return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    basic:
      realm: "integration"
      users:
        - username: %q
          password_hash: %s
`, target, username, passwordHashField)
}

func TestProxyBasic_ValidCredentialIsProxied(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	// The hash is written unquoted and unescaped, exactly as htpasswd
	// prints it, to prove the $-signs survive config loading untouched.
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", hash))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyBasic_MissingCredentialIsChallenged(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", hash))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, header, _, err := testutil.FetchWith(context.Background(), baseURL+"/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, `Basic realm="integration", charset="UTF-8"`, header.Get("WWW-Authenticate"))
}

func TestProxyBasic_WrongPasswordIsRejected(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", hash))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, _, _, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "wrong"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)

	status, _, _, err = testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("mallory", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status, "an unknown user is rejected exactly like a wrong password")
}

func TestProxyBasic_UserChangeHotReloads(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", hash))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "hunter2"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "backend-ok", body)

	// Rename the user: alice must stop working (proving the verified
	// credential cache is dropped on a config change, not just that the
	// new config loaded) and bob must start.
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "bob", hash))

	assertHeaderStatusEventually(t, baseURL+"/", basicHeader("alice", "hunter2"), http.StatusUnauthorized, 5*time.Second)
	assertHeaderStatusEventually(t, baseURL+"/", basicHeader("bob", "hunter2"), http.StatusOK, 5*time.Second)

	// ...and bob genuinely reaches the backend, rather than merely
	// getting some other 200 out of the proxy.
	_, _, body, err = testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("bob", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyBasic_PasswordHashFromEnvReference(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", `"${env:INTEGRATION_BASIC_HASH}"`))

	proc := testutil.StartProxyWith(t, []string{"INTEGRATION_BASIC_HASH=" + hash}, "--config", cfgPath)
	baseURL := "http://" + proc.Addr

	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyBasic_PasswordHashFromFileReference(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	dir := t.TempDir()
	// Written with a trailing newline, the way `htpasswd ... > file`
	// and most secret tooling leaves it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alice.bcrypt"), []byte(hash+"\n"), 0o600))

	cfgPath := filepath.Join(dir, "config.yaml")
	// A relative path, resolved against the config file's own directory.
	testutil.WriteAtomic(t, cfgPath, basicConfigYAML(backend.URL, "alice", `"${file:alice.bcrypt}"`))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

func TestProxyBasic_JSONOverrideFromEnv(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	hash, err := basicHash()
	require.NoError(t, err)

	override := fmt.Sprintf(`{"realm":"from-env","users":[{"username":"alice","password_hash":%q}]}`, hash)

	proc := testutil.StartProxyWith(t,
		[]string{"TAP_TARGET=" + backend.URL, "TAP_INBOUND_AUTH_BASIC_JSON=" + override},
		"--listen-addr", "127.0.0.1:0")
	baseURL := "http://" + proc.Addr

	// No config file at all: basic auth is configurable from env/flags
	// alone, like every other source.
	status, header, _, err := testutil.FetchWith(context.Background(), baseURL+"/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, `Basic realm="from-env", charset="UTF-8"`, header.Get("WWW-Authenticate"))

	status, _, body, err := testutil.FetchWith(context.Background(), baseURL+"/", basicHeader("alice", "hunter2"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "backend-ok", body)
}

// assertHeaderStatusEventually is assertStatusEventually with request
// headers — the reload cases need to poll while presenting a
// credential, which the header-less version can't do.
func assertHeaderStatusEventually(t *testing.T, url string, header http.Header, wantStatus int, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		status, _, _, err := testutil.FetchWith(ctx, url, header)
		if err == nil && status == wantStatus {
			return
		}
		lastStatus, lastErr = status, err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return status %d; last status=%d last err=%v", url, wantStatus, lastStatus, lastErr)
}
