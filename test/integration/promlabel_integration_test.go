//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

const promLabelBlock = `
outbound:
  prom_label_proxy:
    path_prefixes:
      - /prometheus
    exempt:
      - mode: basic
        username: alice
    rules:
      - principals:
          - mode: jwt
            source: ci
        labels:
          - name: %s
            claim: groups
            pattern: "tenant-(.+)"
`

const promRules = `{"status":"success","data":{"groups":[{"name":"g","rules":[
 {"name":"mine","labels":{"namespace":"a"}},
 {"name":"theirs","labels":{"namespace":"b"}}]}]}}`

type promBackend struct {
	*httptest.Server
	mu    sync.Mutex
	query string
}

func newPromBackend(t *testing.T) *promBackend {
	t.Helper()
	b := &promBackend{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/rules") {
			_, _ = io.WriteString(w, promRules)
			return
		}
		b.mu.Lock()
		b.query = r.URL.Path + "?" + r.URL.Query().Get("query")
		b.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *promBackend) received() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.query
}

func TestPromLabelProxy_RealBinary(t *testing.T) {
	idp := testutil.NewTestIDP(t)
	backend := newPromBackend(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	config := func(label string) string {
		return aclConfigYAML(t, backend.URL, idp, fmt.Sprintf(promLabelBlock, label))
	}
	require.NoError(t, os.WriteFile(path, []byte(config("namespace")), 0o600))
	proxy := testutil.StartProxy(t, path)

	token := idp.Sign(t, jwt.MapClaims{
		"iss":    idp.Issuer,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"sub":    "bot",
		"groups": []string{"tenant-a"},
	})
	bearer := http.Header{"Authorization": {"Bearer " + token}}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	queryURL := "http://" + proxy.Addr + "/prometheus/api/v1/query?" + url.Values{"query": {"up"}}.Encode()

	t.Run("query reaches the backend enforced", func(t *testing.T) {
		status, _, _, err := testutil.FetchWith(ctx, queryURL, bearer)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, `/prometheus/api/v1/query?up{namespace="a"}`, backend.received())
	})

	t.Run("rules are filtered under a prefix", func(t *testing.T) {
		status, _, body, err := testutil.FetchWith(ctx, "http://"+proxy.Addr+"/prometheus/api/v1/rules", bearer)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "mine")
		assert.NotContains(t, body, "theirs")
	})

	t.Run("unenforced path is refused", func(t *testing.T) {
		status, _, _, err := testutil.FetchWith(ctx, "http://"+proxy.Addr+"/prometheus/api/v1/read", bearer)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("a typo on reload keeps the previous config", func(t *testing.T) {
		broken := strings.Replace(config("namespace"), "    rules:", "    rulez:", 1)
		testutil.WriteAtomic(t, path, broken)
		time.Sleep(time.Second)
		status, _, _, err := testutil.FetchWith(ctx, queryURL, bearer)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, `/prometheus/api/v1/query?up{namespace="a"}`, backend.received())
	})

	t.Run("a new rule hot-reloads", func(t *testing.T) {
		testutil.WriteAtomic(t, path, config("team"))
		require.Eventually(t, func() bool {
			_, _, _, err := testutil.FetchWith(ctx, queryURL, bearer)
			return err == nil && backend.received() == `/prometheus/api/v1/query?up{team="a"}`
		}, 10*time.Second, 100*time.Millisecond)
	})
}
