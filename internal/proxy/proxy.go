// Package proxy builds the stdlib-based reverse proxy handler and its
// supporting outbound transport.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// ConfigSource supplies the currently-live config. It's implemented by
// *config.Watcher; kept as a narrow interface here so proxy_test.go can
// swap in a lightweight test double instead of standing up a real
// filesystem watcher.
type ConfigSource interface {
	Current() *config.Config
}

// New builds a reverse proxy that forwards every request to source's
// current target, re-read on every request via Rewrite. Because the
// target is read exactly once at the start of handling, a request
// already in flight is unaffected by a target swap that happens while
// it's outstanding — it always completes against the backend it started
// with.
func New(source ConfigSource, logger *slog.Logger, transport http.RoundTripper) *httputil.ReverseProxy {
	if logger == nil {
		logger = slog.Default()
	}

	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(source.Current().TargetURL())
			pr.SetXForwarded()
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("proxy error", "err", err, "path", r.URL.Path)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// BuildTransport constructs the outbound http.Transport used for every
// proxied request, using dial/response-header timeouts from cfg. This is
// built once at startup from the initial config — timeouts are not part
// of the hot-reloadable surface (see config.Config's doc comment).
func BuildTransport(cfg *config.Config) *http.Transport {
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Dial}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: cfg.Timeouts.ResponseHeader,
		ForceAttemptHTTP2:     true,
	}
}

// HealthzHandler reports process liveness without touching the backend —
// mounted alongside the reverse proxy so Kubernetes probes have something
// to hit, since the container image ships no shell and thus no Docker
// HEALTHCHECK.
func HealthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}
