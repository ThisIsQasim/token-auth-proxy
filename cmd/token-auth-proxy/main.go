// Command token-auth-proxy is a minimal HTTP reverse proxy: it forwards
// every request to a single backend target, hot-reloading that target
// from disk without a process restart when configured via --config, or
// taking a static target from CLI flags/environment variables otherwise
// (see internal/config.Resolve for the precedence between them).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/ThisIsQasim/token-auth-proxy/internal/authn"
	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/proxy"
	"github.com/ThisIsQasim/token-auth-proxy/internal/telemetry"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	fs := pflag.NewFlagSet("token-auth-proxy", pflag.ContinueOnError)
	config.RegisterFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	providers, err := telemetry.Setup(ctx, logger)
	if err != nil {
		return fmt.Errorf("set up telemetry: %w", err)
	}
	// Deferred immediately on success, not further down with
	// authRegistry.Close()/samlRegistry.Close() below — a later
	// early-return (e.g. config.Resolve or config.NewWatcher failing)
	// must not skip shutting down whatever Setup already started (e.g.
	// an OTLP batch processor's background goroutine), even though in
	// practice main() os.Exit(1)s right after and the process teardown
	// masks it either way.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := providers.Shutdown(shutdownCtx); err != nil {
			logger.Error("telemetry shutdown failed", "err", err)
		}
	}()
	// From here on, every existing logger.Info(...)/logger.Error(...)
	// call site, unmodified, automatically forwards to the OTel Logs SDK
	// too, once configured (see telemetry.Setup's doc comment) — the
	// stdout JSON shape integration tests parse is unaffected either
	// way.
	logger = providers.Logger
	slog.SetDefault(logger)

	src, err := config.Resolve(fs)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	var source proxy.ConfigSource
	var watcher *config.Watcher

	if src.ConfigPath != "" {
		w, err := config.NewWatcher(src.ConfigPath, src.FlagSet, logger)
		if err != nil {
			return fmt.Errorf("load initial config: %w", err)
		}
		source, watcher = w, w
	} else {
		source = config.NewStaticSource(src.Config)
		logger.Info("no --config/TAP_CONFIG set: running with a static configuration, no hot-reload")
	}

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	if watcher != nil {
		go func() {
			if err := watcher.Start(watchCtx); err != nil {
				logger.Error("config watcher stopped unexpectedly", "err", err)
			}
		}()
	}

	cfg := source.Current()
	if cfg.Inbound.Auth.JWTEnabled() {
		logger.Info("jwt verification enabled", "jwt_sources", len(cfg.Inbound.Auth.JWT))
	}
	if cfg.Inbound.Auth.SAMLEnabled() {
		samlSrc := cfg.Inbound.Auth.SAML
		logger.Info("saml sp login enabled",
			"saml_source", samlSrc.Name,
			"acs_path", samlSrc.ACSPath,
			"sp_entity_id", samlSrc.SPEntityID)
		if !strings.HasPrefix(samlSrc.SPBaseURL, "https://") {
			// Browsers only honor SameSite=None (required for the IdP's
			// cross-site ACS POST — see buildSAMLProvider's doc comment)
			// on Secure cookies. Warn, don't reject: every other URL
			// field in this schema (target, jwks_url, idp_metadata_url)
			// already permits http, including for legitimate local-dev
			// and integration-test use, and this proxy's own
			// integration tests need http://127.0.0.1 to work at all.
			logger.Warn("saml sp_base_url is not https: real browsers will not send the ACS tracking cookie back cross-site, so login will not work outside local dev/test",
				"sp_base_url", samlSrc.SPBaseURL)
		}
	}

	authRegistry := authn.NewRegistry(logger)
	samlRegistry := authn.NewSAMLRegistry(logger)
	// Deferred here (not earlier/later) so both fire after srv.Shutdown
	// below returns — in-flight requests during graceful shutdown can
	// still verify against a live resolver/provider.
	defer authRegistry.Close()
	defer samlRegistry.Close()

	transport := proxy.BuildTransport(cfg)
	rp := proxy.New(source, logger, transport)
	requireAuth := authn.NewMiddleware(source, authRegistry, samlRegistry, logger)

	mux := http.NewServeMux()
	mux.Handle("/healthz", proxy.HealthzHandler())   // deliberately unauthenticated
	mux.Handle("/metrics", providers.MetricsHandler) // deliberately unauthenticated, always mounted regardless of OTLP config
	// requireAuth is installed unconditionally, even with nothing
	// configured now — a later hot-reload can add a source, and the
	// fully-disabled path costs two atomic config loads per request.
	// otelhttp wraps only this route (not /healthz or /metrics), so
	// health/metrics polling doesn't spam traces or double-count in its
	// own metrics.
	mux.Handle("/", otelhttp.NewMiddleware("token-auth-proxy")(requireAuth(rp)))

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("bind listener on %s: %w", cfg.ListenAddr, err)
	}
	logger.Info("listening", "addr", ln.Addr().String(), "target", cfg.Target)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.Timeouts.ReadHeader,
		ReadTimeout:       cfg.Timeouts.Read,
		WriteTimeout:      cfg.Timeouts.Write,
		IdleTimeout:       cfg.Timeouts.Idle,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
		}
	}

	cancelWatch()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}
