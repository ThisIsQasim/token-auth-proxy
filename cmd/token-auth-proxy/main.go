// Command token-auth-proxy is a minimal HTTP reverse proxy: it forwards
// every request to a single backend target defined in a YAML config file,
// hot-reloading that target from disk without a process restart.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	configPath := flag.String("config", "", "path to YAML config file (required)")
	flag.Parse()

	if *configPath == "" {
		flag.Usage()
		return fmt.Errorf("usage: token-auth-proxy -config <path>")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	watcher, err := config.NewWatcher(*configPath, logger)
	if err != nil {
		return fmt.Errorf("load initial config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go func() {
		if err := watcher.Start(watchCtx); err != nil {
			logger.Error("config watcher stopped unexpectedly", "err", err)
		}
	}()

	cfg := watcher.Current()
	transport := proxy.BuildTransport(cfg)
	rp := proxy.New(watcher, logger, transport)

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
