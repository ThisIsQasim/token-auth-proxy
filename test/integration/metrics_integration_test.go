//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

// TestProxyMetrics_EndpointServesPrometheusFormat proves /metrics is
// mounted, unauthenticated, and in real Prometheus exposition format —
// with zero OTEL_* env vars set, i.e. the always-on path telemetry.Setup
// guarantees regardless of OTLP configuration (see its doc comment).
// Driving one rejected request first proves the authn.rejections custom
// counter (internal/authn/metrics.go) actually reaches the same
// registry /metrics scrapes, not just that the Prometheus handler
// itself works.
func TestProxyMetrics_EndpointServesPrometheusFormat(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	// Drive one rejection so authn.rejections has a non-zero sample to
	// find below.
	assertRejected(t, baseURL+"/", nil)

	var metricsBody string
	require.Eventually(t, func() bool {
		var ferr error
		metricsBody, ferr = testutil.FetchBody(context.Background(), baseURL+"/metrics")
		return ferr == nil && strings.Contains(metricsBody, "authn_rejections_total")
	}, 3*time.Second, 50*time.Millisecond, "authn_rejections_total should appear in /metrics after a rejected request")

	assert.Contains(t, metricsBody, "# TYPE", "should be real Prometheus exposition format")
	assert.Contains(t, metricsBody, "authn_rejections_total{")
	assert.Contains(t, metricsBody, `reason="no_credential"`)
}

// TestProxyMetrics_HealthzAndMetricsStayUnauthenticated confirms /metrics
// and /healthz both bypass authn even with JWT enforcement configured —
// mirrors the existing TestProxyJWT_HealthzStaysUnauthenticated
// coverage for /healthz, extended to /metrics.
func TestProxyMetrics_HealthzAndMetricsStayUnauthenticated(t *testing.T) {
	backend := testutil.NewBackend(t, "backend-ok")
	idp := testutil.NewTestIDP(t)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, fmt.Sprintf(`
listen_addr: ":0"
target: %q
inbound:
  auth:
    jwt:
%s`, backend.URL, jwtSourceYAML(idp)))

	proc := testutil.StartProxy(t, cfgPath)
	baseURL := "http://" + proc.Addr

	for _, path := range []string{"/healthz", "/metrics"} {
		status, _, body, err := testutil.FetchWith(context.Background(), baseURL+path, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status, "%s should stay unauthenticated even with JWT enforcement configured", path)
		// Both are served by the proxy itself, off the authenticated
		// route entirely — so neither may be answered by the backend.
		assertNotBackend(t, body)
	}
}
