// Package telemetry owns all OpenTelemetry setup for the proxy: traces,
// metrics (both OTLP-pushed and always-on Prometheus-pulled via
// /metrics), and logs. Mirrors internal/authn's Registry pattern — own
// your lifecycle, expose a Shutdown.
//
// There are deliberately no proxy-specific YAML/TAP_ config fields here.
// The OTel ecosystem already has a mature, standardized environment
// variable surface (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME,
// OTEL_RESOURCE_ATTRIBUTES, per-signal OTEL_EXPORTER_OTLP_*_ENDPOINT,
// ...) that operators of any OTel-instrumented service already know;
// duplicating it into this project's own schema would just be a worse,
// non-standard reimplementation of what the SDK's own env-aware
// constructors already read. See https://opentelemetry.io/docs/specs/otel/protocol/exporter/
// for the full list.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	prometheusclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	logglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// serviceName is the default OTEL_SERVICE_NAME / service.name resource
// attribute value. resource.WithFromEnv runs after this in Setup, so
// OTEL_SERVICE_NAME/OTEL_RESOURCE_ATTRIBUTES override it, not the other
// way around.
const serviceName = "token-auth-proxy"

// newSpanExporter, newMetricReader, and newLogExporter are Setup's
// exporter-construction seams — package-level vars, not direct
// autoexport.* calls, purely so tests can swap in an in-memory exporter
// (e.g. stdouttrace/stdoutmetric/stdoutlog) instead of a real
// network-facing OTLP exporter to assert Setup's wiring is correct
// without a live collector. Production code never reassigns these.
var (
	newSpanExporter = autoexport.NewSpanExporter
	newMetricReader = autoexport.NewMetricReader
	newLogExporter  = autoexport.NewLogExporter
)

// Providers holds everything main.go needs after telemetry setup: the
// (possibly OTel-log-wrapped) logger to use from that point on, the
// always-on Prometheus scrape handler for /metrics, and a single
// Shutdown to defer.
type Providers struct {
	Logger         *slog.Logger
	MetricsHandler http.Handler
	Shutdown       func(context.Context) error
}

// otelConfigured reports whether OTLP export is configured for signal
// ("TRACES", "METRICS", or "LOGS"), matching the spec's own precedence:
// the general OTEL_EXPORTER_OTLP_ENDPOINT, or that signal's own
// OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT.
func otelConfigured(signal string) bool {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		return true
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT") != ""
}

// Setup builds the resource and, per signal, either a real OTLP-backed
// provider (only if that signal is configured via OTEL_* env vars — see
// otelConfigured) or leaves the OTel API's own no-op default in place.
// Metrics are the one exception: a Prometheus reader is always
// constructed and always live, so /metrics works with zero
// configuration.
//
// baseLogger is returned unchanged in Providers.Logger unless logs are
// configured, in which case it's wrapped in a fan-out multiHandler so
// stdout JSON logging (which integration tests parse directly) keeps
// its exact existing shape either way.
func Setup(ctx context.Context, baseLogger *slog.Logger) (*Providers, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithHost(),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: build resource: %w", err)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	var shutdowns []func(context.Context) error

	if otelConfigured("TRACES") {
		exp, err := newSpanExporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: build trace exporter: %w", err)
		}
		tp := trace.NewTracerProvider(trace.WithBatcher(exp), trace.WithResource(res))
		otel.SetTracerProvider(tp)
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	promReg := prometheusclient.NewRegistry()
	promExp, err := prometheus.New(prometheus.WithRegisterer(promReg))
	if err != nil {
		return nil, fmt.Errorf("telemetry: build prometheus exporter: %w", err)
	}
	meterOpts := []metric.Option{metric.WithReader(promExp), metric.WithResource(res)}
	if otelConfigured("METRICS") {
		reader, err := newMetricReader(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: build metric reader: %w", err)
		}
		meterOpts = append(meterOpts, metric.WithReader(reader))
	}
	mp := metric.NewMeterProvider(meterOpts...)
	otel.SetMeterProvider(mp)
	shutdowns = append(shutdowns, mp.Shutdown)

	logger := baseLogger
	if otelConfigured("LOGS") {
		exp, err := newLogExporter(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: build log exporter: %w", err)
		}
		lp := log.NewLoggerProvider(
			log.WithProcessor(log.NewBatchProcessor(exp)),
			log.WithResource(res),
		)
		logglobal.SetLoggerProvider(lp)
		shutdowns = append(shutdowns, lp.Shutdown)

		otelHandler := otelslog.NewHandler(serviceName, otelslog.WithLoggerProvider(lp))
		logger = slog.New(newMultiHandler(baseLogger.Handler(), otelHandler))
	}

	return &Providers{
		Logger:         logger,
		MetricsHandler: promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}),
		Shutdown: func(ctx context.Context) error {
			var errs []error
			for _, shutdown := range shutdowns {
				if err := shutdown(ctx); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}, nil
}
