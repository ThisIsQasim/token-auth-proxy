//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

// aclConfigYAML renders a config trusting Basic user alice and idp as JWT
// source "ci", followed by aclYAML verbatim at the top level.
func aclConfigYAML(t *testing.T, target string, idp *testutil.TestIDP, aclYAML string) string {
	t.Helper()
	hash, err := basicHash()
	require.NoError(t, err)
	return fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    basic:
      users:
        - username: alice
          password_hash: %s
    jwt:
      - name: ci
        issuer: %q
        jwks_url: %q
%s`, target, hash, idp.Issuer, idp.JWKSURL, aclYAML)
}

const aclAliceWritesBotReads = `
acl:
  - principals:
      - mode: basic
        subject: alice
    methods:
      - POST
    paths:
      - /api/v1/push
  - principals:
      - mode: jwt
        source: ci
        claims:
          groups: readers
    methods:
      - GET
    paths:
      - /prometheus/*
`

const aclSwapped = `
acl:
  - principals:
      - mode: jwt
        source: ci
        claims:
          groups: readers
    methods:
      - POST
    paths:
      - /api/v1/push
`

// doRequest sends method to url with header and returns the status and
// body, without treating a non-200 as an error.
func doRequest(t *testing.T, method, url string, header http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	require.NoError(t, err)
	req.Header = header.Clone()
	client := &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func assertAllowed(t *testing.T, method, url string, header http.Header) {
	t.Helper()
	status, body := doRequest(t, method, url, header)
	assert.Equal(t, http.StatusOK, status, "%s %s", method, url)
	assert.Equal(t, backendBody, body, "the backend's own response must reach the client unchanged")
}

func assertForbidden(t *testing.T, method, url string, header http.Header) {
	t.Helper()
	status, body := doRequest(t, method, url, header)
	assert.Equal(t, http.StatusForbidden, status, "%s %s", method, url)
	assert.Equal(t, "forbidden", body)
}

func readerToken(t *testing.T, idp *testutil.TestIDP) string {
	t.Helper()
	return idp.Sign(t, jwt.MapClaims{
		"iss":    idp.Issuer,
		"sub":    "grafana",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"groups": []string{"readers"},
	})
}

func TestProxyACL_AllowsAndDeniesPerRule(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, aclConfigYAML(t, backend.URL, idp, aclAliceWritesBotReads))
	proc := testutil.StartProxy(t, cfgPath)
	base := "http://" + proc.Addr

	alice := basicHeader("alice", "hunter2")
	reader := bearerHeader(readerToken(t, idp))

	assertAllowed(t, http.MethodPost, base+"/api/v1/push", alice)
	assertForbidden(t, http.MethodGet, base+"/api/v1/push", alice)
	assertForbidden(t, http.MethodGet, base+"/prometheus/api/v1/query", alice)

	assertAllowed(t, http.MethodGet, base+"/prometheus/api/v1/query", reader)
	assertForbidden(t, http.MethodPost, base+"/prometheus/api/v1/query", reader)
	assertForbidden(t, http.MethodPost, base+"/api/v1/push", reader)

	// Authentication failures are still 401s, not 403s.
	status, body := doRequest(t, http.MethodPost, base+"/api/v1/push", basicHeader("alice", "wrong"))
	assert.Equal(t, http.StatusUnauthorized, status)
	assertNotBackend(t, body)

	// An encoded slash could be decoded differently by the backend.
	assertForbidden(t, http.MethodGet, base+"/prometheus/a%2F..%2F..%2Fadmin", reader)
	// A dot-dot path never reaches the backend as-is.
	status, body = doRequest(t, http.MethodGet, base+"/prometheus/../admin", reader)
	assert.NotEqual(t, http.StatusOK, status)
	assertNotBackend(t, body)
}

func TestProxyACL_HotReloadFlipsDecision(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, aclConfigYAML(t, backend.URL, idp, aclAliceWritesBotReads))
	proc := testutil.StartProxy(t, cfgPath)
	pushURL := "http://" + proc.Addr + "/api/v1/push"

	alice := basicHeader("alice", "hunter2")
	reader := bearerHeader(readerToken(t, idp))

	assertAllowed(t, http.MethodPost, pushURL, alice)
	assertForbidden(t, http.MethodPost, pushURL, reader)

	testutil.WriteAtomic(t, cfgPath, aclConfigYAML(t, backend.URL, idp, aclSwapped))
	assertMethodStatusEventually(t, http.MethodPost, pushURL, alice, http.StatusForbidden, 5*time.Second)
	assertForbidden(t, http.MethodPost, pushURL, alice)
	assertAllowed(t, http.MethodPost, pushURL, reader)

	// Removing the ACL entirely allows every authenticated request again.
	testutil.WriteAtomic(t, cfgPath, aclConfigYAML(t, backend.URL, idp, ""))
	assertMethodStatusEventually(t, http.MethodDelete, "http://"+proc.Addr+"/anything", alice, http.StatusOK, 5*time.Second)
	assertAllowed(t, http.MethodDelete, "http://"+proc.Addr+"/anything", alice)
	assertAllowed(t, http.MethodPut, "http://"+proc.Addr+"/anything", reader)
}

func TestProxyACL_FromFlags(t *testing.T) {
	backend := testutil.NewBackend(t, backendBody)
	hash, err := basicHash()
	require.NoError(t, err)

	proc := testutil.StartProxyArgs(t,
		"--listen-addr", ":0",
		"--target", backend.URL,
		"--inbound-auth-basic-json", fmt.Sprintf(`{"users":[{"username":"alice","password_hash":%q}]}`, hash),
		"--acl-json", `[{"principals":[{"mode":"basic","subject":"alice"}],"methods":["*"],"paths":["/ok/*"]}]`,
	)
	base := "http://" + proc.Addr
	alice := basicHeader("alice", "hunter2")

	assertAllowed(t, http.MethodGet, base+"/ok/x", alice)
	assertAllowed(t, http.MethodPost, base+"/ok/y", alice)
	assertForbidden(t, http.MethodGet, base+"/nope", alice)
}

func assertMethodStatusEventually(t *testing.T, method, url string, header http.Header, wantStatus int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last int
	for time.Now().Before(deadline) {
		if last, _ = doRequest(t, method, url, header); last == wantStatus {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s %s to return %d; last status=%d", method, url, wantStatus, last)
}
