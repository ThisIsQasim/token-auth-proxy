//go:build load

// Package load is a soak test proving the atomic-swap reload path is safe
// under real concurrent contention, not just correct in a single-threaded
// unit test. It attacks the real exec'd binary at a fixed rate while a
// background goroutine continuously flips the config file between two
// backends, and records both request latency (via vegeta) and the proxy
// process's own CPU/memory usage (via gopsutil) for the run.
//
// Two scenarios run back to back, sharing the same core attack logic:
// "baseline" (no inbound.auth at all) and "jwt-auth" (a real JWT source
// enabled, a real signed bearer token attached to every request). Kept
// side by side deliberately, not replaced one-for-the-other: baseline
// alone would never measure the per-request verification cost that's
// the whole reason this proxy exists, but jwt-auth alone would lose the
// ability to see that cost as a delta against an unauthenticated
// pass-through. jwt-auth additionally exercises Registry.Reconcile/
// Keyfunc under the same sustained concurrent-request-plus-concurrent-
// reload conditions the target swap itself is already tested under.
//
// Run via `make test-load` or `go test -tags=load ./test/load/...`. Set
// LOAD_TEST_REPORT_PATH to have each scenario's metrics written out as
// JSON (suffixed with the scenario name, e.g. `-baseline`/`-jwt-auth`,
// so the two don't overwrite each other) — CI uploads these as a build
// artifact so results are inspectable after the fact, not just pass/fail.
package load

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vegeta "github.com/tsenart/vegeta/v12/lib"

	"github.com/ThisIsQasim/token-auth-proxy/test/testutil"
)

const (
	attackDuration  = 8 * time.Second
	attackRate      = 200 // requests/sec
	flipInterval    = 200 * time.Millisecond
	resourceSampleP = 250 * time.Millisecond

	minSuccessRate = 0.99
	maxP99Latency  = 250 * time.Millisecond
)

// resourceSample is one point-in-time reading of the proxy process's
// resource usage.
type resourceSample struct {
	CPUPercent float64
	RSSBytes   uint64
}

// resourceSummary aggregates samples collected over the run.
type resourceSummary struct {
	Samples        int     `json:"samples"`
	PeakCPUPercent float64 `json:"peak_cpu_percent"`
	AvgCPUPercent  float64 `json:"avg_cpu_percent"`
	PeakRSSBytes   uint64  `json:"peak_rss_bytes"`
	AvgRSSBytes    uint64  `json:"avg_rss_bytes"`
}

func summarizeResources(samples []resourceSample) resourceSummary {
	var s resourceSummary
	s.Samples = len(samples)
	if len(samples) == 0 {
		return s
	}
	var cpuSum float64
	var rssSum uint64
	for _, sample := range samples {
		cpuSum += sample.CPUPercent
		rssSum += sample.RSSBytes
		if sample.CPUPercent > s.PeakCPUPercent {
			s.PeakCPUPercent = sample.CPUPercent
		}
		if sample.RSSBytes > s.PeakRSSBytes {
			s.PeakRSSBytes = sample.RSSBytes
		}
	}
	s.AvgCPUPercent = cpuSum / float64(len(samples))
	s.AvgRSSBytes = rssSum / uint64(len(samples))
	return s
}

// sampleResources polls the given pid's CPU% and RSS every
// resourceSampleP until ctx is canceled, sending each reading on the
// returned channel (buffered generously; the caller drains it after
// closing has been signaled).
func sampleResources(ctx context.Context, pid int32) <-chan resourceSample {
	out := make(chan resourceSample, 1024)
	go func() {
		defer close(out)
		proc, err := process.NewProcess(pid)
		if err != nil {
			return
		}
		ticker := time.NewTicker(resourceSampleP)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cpuPct, err := proc.Percent(0)
				if err != nil {
					continue
				}
				mem, err := proc.MemoryInfo()
				if err != nil {
					continue
				}
				select {
				case out <- resourceSample{CPUPercent: cpuPct, RSSBytes: mem.RSS}:
				default:
				}
			}
		}
	}()
	return out
}

// latencyReport is the JSON shape written to LOAD_TEST_REPORT_PATH.
type latencyReport struct {
	Name        string          `json:"name"`
	Requests    uint64          `json:"requests"`
	Success     float64         `json:"success"`
	Throughput  float64         `json:"throughput_rps"`
	LatencyP50  string          `json:"latency_p50"`
	LatencyP95  string          `json:"latency_p95"`
	LatencyP99  string          `json:"latency_p99"`
	LatencyMax  string          `json:"latency_max"`
	StatusCodes map[string]int  `json:"status_codes"`
	Errors      []string        `json:"errors,omitempty"`
	Resources   resourceSummary `json:"resources"`
}

// writeReport writes r's JSON to LOAD_TEST_REPORT_PATH (defaulting to
// "load-test-report.json"), suffixed with r.Name before the extension —
// e.g. "load-test-report-baseline.json" — so the baseline and jwt-auth
// scenarios in the same run don't overwrite each other's file, even
// though CI sets one shared LOAD_TEST_REPORT_PATH for the whole
// package.
func writeReport(tb testing.TB, r latencyReport) {
	tb.Helper()
	path := os.Getenv("LOAD_TEST_REPORT_PATH")
	if path == "" {
		path = "load-test-report.json"
	}
	ext := filepath.Ext(path)
	path = strings.TrimSuffix(path, ext) + "-" + r.Name + ext

	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		tb.Logf("failed to marshal load test report: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // report is not sensitive
		tb.Logf("failed to write load test report to %s: %v", path, err)
		return
	}
	tb.Logf("wrote load test report to %s", path)
}

// authScenario optionally attaches JWT bearer-token auth to a
// runHotReloadLoadTest run. A nil *authScenario means the proxy runs
// with no inbound.auth at all — both configYAML and header are safe to
// call on a nil receiver, checking explicitly rather than requiring
// every call site to branch on nilness itself.
type authScenario struct {
	idp   *testutil.TestIDP
	token string
}

// newJWTAuthScenario starts a real JWKS server and signs one token,
// reused for the whole attack — a real client holds onto a token until
// it expires too, rather than re-signing per request, so this measures
// the proxy's actual verification cost (a JWKS-cached signature check),
// not token-minting cost that wouldn't exist in the real request path.
func newJWTAuthScenario(t *testing.T) *authScenario {
	idp := testutil.NewTestIDP(t)
	token := idp.Sign(t, jwt.RegisteredClaims{
		Issuer:    idp.Issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(attackDuration + time.Minute)),
	})
	return &authScenario{idp: idp, token: token}
}

func (a *authScenario) configYAML(listenAddr, target string) string {
	if a == nil {
		return testutil.ConfigYAML(listenAddr, target)
	}
	return fmt.Sprintf(`
listen_addr: %q
target: %q
inbound:
  auth:
    jwt:
      - name: idp
        issuer: %q
        jwks_url: %q
`, listenAddr, target, a.idp.Issuer, a.idp.JWKSURL)
}

func (a *authScenario) header() http.Header {
	if a == nil {
		return nil
	}
	return http.Header{"Authorization": []string{"Bearer " + a.token}}
}

// runHotReloadLoadTest is the shared core of both scenarios below: it
// attacks a real proxy process at a fixed rate while continuously
// flipping its backend target, records latency and resource usage, and
// asserts on the same generous, noise-tolerant thresholds regardless of
// scenario. reportName both labels the written report/vegeta attack and
// (via authScenario.configYAML/header) selects whether auth is enabled.
func runHotReloadLoadTest(t *testing.T, reportName string, auth *authScenario) {
	t.Helper()
	backendA := testutil.NewBackend(t, "A")
	backendB := testutil.NewBackend(t, "B")

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	testutil.WriteAtomic(t, cfgPath, auth.configYAML(":0", backendA.URL))

	proc := testutil.StartProxy(t, cfgPath)
	targetURL := "http://" + proc.Addr + "/"

	flipCtx, stopFlipping := context.WithCancel(context.Background())
	defer stopFlipping()
	go func() {
		urls := [2]string{backendA.URL, backendB.URL}
		i := 0
		ticker := time.NewTicker(flipInterval)
		defer ticker.Stop()
		for {
			select {
			case <-flipCtx.Done():
				return
			case <-ticker.C:
				i++
				testutil.WriteAtomic(t, cfgPath, auth.configYAML(":0", urls[i%2]))
			}
		}
	}()

	resourceCtx, stopSampling := context.WithCancel(context.Background())
	resourceCh := sampleResources(resourceCtx, int32(proc.Cmd.Process.Pid)) //nolint:gosec // pid is always positive

	targeter := vegeta.NewStaticTargeter(vegeta.Target{Method: "GET", URL: targetURL, Header: auth.header()})
	attacker := vegeta.NewAttacker()
	rate := vegeta.Rate{Freq: attackRate, Per: time.Second}

	var metrics vegeta.Metrics
	for res := range attacker.Attack(targeter, rate, attackDuration, reportName) {
		metrics.Add(res)
	}
	metrics.Close()

	stopFlipping()
	stopSampling()

	var samples []resourceSample
	for s := range resourceCh {
		samples = append(samples, s)
	}
	resSummary := summarizeResources(samples)

	report := latencyReport{
		Name:        reportName,
		Requests:    metrics.Requests,
		Success:     metrics.Success,
		Throughput:  metrics.Throughput,
		LatencyP50:  metrics.Latencies.P50.String(),
		LatencyP95:  metrics.Latencies.P95.String(),
		LatencyP99:  metrics.Latencies.P99.String(),
		LatencyMax:  metrics.Latencies.Max.String(),
		StatusCodes: metrics.StatusCodes,
		Errors:      metrics.Errors,
		Resources:   resSummary,
	}
	writeReport(t, report)

	t.Logf("[%s] requests=%d success=%.4f throughput=%.1f/s p50=%s p95=%s p99=%s max=%s",
		reportName, metrics.Requests, metrics.Success, metrics.Throughput,
		metrics.Latencies.P50, metrics.Latencies.P95, metrics.Latencies.P99, metrics.Latencies.Max)
	t.Logf("[%s] resources: samples=%d peak_cpu=%.1f%% avg_cpu=%.1f%% peak_rss=%dMB avg_rss=%dMB",
		reportName, resSummary.Samples, resSummary.PeakCPUPercent, resSummary.AvgCPUPercent,
		resSummary.PeakRSSBytes/1024/1024, resSummary.AvgRSSBytes/1024/1024)

	// Deliberately generous thresholds — this catches a broken lock,
	// deadlock, or panic in the swap path, not tight SLOs, since shared
	// CI runners are noisy.
	assert.GreaterOrEqual(t, metrics.Success, minSuccessRate,
		"[%s] expected >=%.0f%% success despite continuous config reloads", reportName, minSuccessRate*100)
	assert.LessOrEqual(t, metrics.Latencies.P99, maxP99Latency,
		"[%s] P99 latency should stay bounded even while reloads are happening", reportName)
	require.NotEmpty(t, samples, "[%s] expected at least one resource usage sample during the attack", reportName)
}

func TestLoad_HotReloadUnderTraffic(t *testing.T) {
	runHotReloadLoadTest(t, "baseline", nil)
}

func TestLoad_HotReloadUnderTraffic_WithJWTAuth(t *testing.T) {
	runHotReloadLoadTest(t, "jwt-auth", newJWTAuthScenario(t))
}
