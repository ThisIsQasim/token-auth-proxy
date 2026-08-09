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
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/proxy"
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

	src, err := config.Resolve(fs)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	transport := proxy.BuildTransport(cfg)
	rp := proxy.New(source, logger, transport)

	mux := http.NewServeMux()
	mux.Handle("/healthz", proxy.HealthzHandler())
	mux.Handle("/", rp)

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
