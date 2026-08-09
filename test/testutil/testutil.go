// Package testutil provides shared helpers for the integration and load
// test packages: building the real binary, running it as a subprocess,
// discovering its bound listen address, and writing config files
// atomically the way a real editor or Kubernetes ConfigMap swap would.
//
// It is intentionally not a _test.go file so it can be imported by both
// //go:build integration and //go:build load test packages.
package testutil

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

// BuildBinary builds cmd/token-auth-proxy once per test process and
// returns the path to the resulting binary. Safe for concurrent use;
// subsequent calls return the same cached path.
func BuildBinary(tb testing.TB) string {
	tb.Helper()

	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "token-auth-proxy-bin-")
		if err != nil {
			buildErr = err
			return
		}
		buildPath = filepath.Join(dir, "token-auth-proxy")

		root := repoRoot(tb)
		// #nosec G204 -- buildPath is our own os.MkdirTemp output, not untrusted input
		cmd := exec.CommandContext(context.Background(), "go", "build", "-o", buildPath, "./cmd/token-auth-proxy")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})

	if buildErr != nil {
		tb.Fatalf("build binary: %v", buildErr)
	}
	return buildPath
}

// repoRoot walks up from the current working directory to find the
// directory containing go.mod, so BuildBinary works regardless of which
// test package invokes it.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

// Process wraps a running proxy subprocess.
type Process struct {
	Cmd  *exec.Cmd
	Addr string

	tb testing.TB
}

// StartProxy builds (if needed) and starts the real proxy binary against
// configPath, waits for it to log its bound listen address, and registers
// a cleanup that sends SIGTERM and waits for exit. configPath's config
// should set listen_addr to ":0" so the OS picks an ephemeral port.
func StartProxy(tb testing.TB, configPath string) *Process {
	tb.Helper()

	bin := BuildBinary(tb)
	// #nosec G204 -- bin is our own just-built binary and configPath is a test-controlled temp file
	cmd := exec.CommandContext(context.Background(), bin, "-config", configPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		tb.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		tb.Fatalf("start proxy: %v", err)
	}

	p := &Process{Cmd: cmd, tb: tb}

	tb.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	p.Addr = waitForListenAddr(tb, stdout, 5*time.Second)
	return p
}

// listeningLog mirrors the JSON shape main.go logs when it binds its
// listener: {"msg":"listening","addr":"127.0.0.1:54321",...}.
type listeningLog struct {
	Msg  string `json:"msg"`
	Addr string `json:"addr"`
}

// waitForListenAddr scans stdout for the "listening" log line and returns
// its addr field, failing the test if it doesn't appear within timeout.
func waitForListenAddr(tb testing.TB, r interface{ Read([]byte) (int, error) }, timeout time.Duration) string {
	tb.Helper()

	type result struct {
		addr string
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			var lg listeningLog
			if err := json.Unmarshal([]byte(line), &lg); err != nil {
				continue
			}
			if lg.Msg == "listening" && lg.Addr != "" {
				ch <- result{addr: lg.Addr}
				return
			}
		}
		ch <- result{err: fmt.Errorf("stdout closed before listening log appeared")}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			tb.Fatalf("waiting for listen addr: %v", res.err)
		}
		return res.addr
	case <-time.After(timeout):
		tb.Fatalf("timed out waiting for proxy to log its listen address")
		return ""
	}
}

// WriteAtomic writes contents to path by writing to a sibling temp file
// and renaming it over path, mirroring how editors and Kubernetes
// ConfigMap volume mounts publish updates — this is what actually
// exercises the watcher's rename-handling path, as opposed to an in-place
// write.
func WriteAtomic(tb testing.TB, path, contents string) {
	tb.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(contents), 0o600); err != nil {
		tb.Fatalf("write temp config: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		tb.Fatalf("rename config into place: %v", err)
	}
}

// NewBackend starts an httptest.Server that responds 200 with body to
// every request, tagged so callers can identify which backend served a
// given proxied response.
func NewBackend(tb testing.TB, body string) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	tb.Cleanup(srv.Close)
	return srv
}

// ConfigYAML renders a minimal config file pointing at target.
func ConfigYAML(listenAddr, target string) string {
	return fmt.Sprintf("listen_addr: %q\ntarget: %q\n", listenAddr, target)
}

// FetchBody performs a GET against url and returns the response body as a
// string, or an error — used by pollers that expect transient failures
// (e.g. during a config reload window) rather than failing the test on
// the first bad response.
func FetchBody(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := strings.TrimSpace(string(buf[:n]))
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return body, nil
}
