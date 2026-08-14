package telemetry

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestOtelConfigured(t *testing.T) {
	tests := []struct {
		name    string
		general string
		signal  string
		want    bool
	}{
		{name: "nothing set", want: false},
		{name: "general endpoint set", general: "http://collector:4318", want: true},
		{name: "signal-specific endpoint set", signal: "http://collector:4318", want: true},
		{name: "both set", general: "http://collector:4318", signal: "http://other:4318", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", tt.general)
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", tt.signal)
			assert.Equal(t, tt.want, otelConfigured("TRACES"))
		})
	}
}

func TestOtelConfigured_SignalsAreIndependent(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://collector:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")

	assert.True(t, otelConfigured("TRACES"))
	assert.False(t, otelConfigured("METRICS"))
	assert.False(t, otelConfigured("LOGS"))
}

// clearOTLPEnv ensures none of the OTLP endpoint env vars leak in from
// the environment the test happens to run in, so "nothing configured"
// tests are actually nothing configured.
func clearOTLPEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
}

func TestSetup_NothingConfigured_LoggerUnchangedAndMetricsHandlerServesPrometheusFormat(t *testing.T) {
	clearOTLPEnv(t)

	var buf bytes.Buffer
	baseLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	providers, err := Setup(context.Background(), baseLogger)
	require.NoError(t, err)
	require.NotNil(t, providers)

	// No signal configured: the logger returned must be the exact same
	// instance handed in, not a wrapped copy — this is what lets every
	// existing logger.Info(...) call site keep working unmodified.
	assert.Same(t, baseLogger, providers.Logger)

	require.NotNil(t, providers.MetricsHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	providers.MetricsHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "# TYPE", "Prometheus handler should always be live, even with no OTLP endpoint configured")

	require.NoError(t, providers.Shutdown(context.Background()))
}

// withExporterSeams temporarily swaps Setup's exporter-construction
// vars, restoring the originals on test cleanup. Signatures must match
// the autoexport.New*Exporter/Reader functions exactly.
func withExporterSeams(t *testing.T, span func(context.Context, ...autoexport.SpanOption) (trace.SpanExporter, error),
	metric func(context.Context, ...autoexport.MetricOption) (sdkmetric.Reader, error),
	logs func(context.Context, ...autoexport.LogOption) (sdklog.Exporter, error)) {
	t.Helper()
	origSpan, origMetric, origLog := newSpanExporter, newMetricReader, newLogExporter
	t.Cleanup(func() {
		newSpanExporter, newMetricReader, newLogExporter = origSpan, origMetric, origLog
	})
	if span != nil {
		newSpanExporter = span
	}
	if metric != nil {
		newMetricReader = metric
	}
	if logs != nil {
		newLogExporter = logs
	}
}

func TestSetup_LogsConfigured_WrapsLoggerAndForwardsToOTel(t *testing.T) {
	clearOTLPEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://127.0.0.1:0")

	var otelOut bytes.Buffer
	withExporterSeams(t, nil, nil, func(context.Context, ...autoexport.LogOption) (sdklog.Exporter, error) {
		return stdoutlog.New(stdoutlog.WithWriter(&otelOut))
	})

	var stdoutBuf bytes.Buffer
	baseLogger := slog.New(slog.NewJSONHandler(&stdoutBuf, nil))

	providers, err := Setup(context.Background(), baseLogger)
	require.NoError(t, err)
	require.NotSame(t, baseLogger, providers.Logger, "logs configured: Logger should be wrapped, not the same instance")

	providers.Logger.Info("hello from test")
	require.NoError(t, providers.Shutdown(context.Background()))

	assert.Contains(t, stdoutBuf.String(), "hello from test", "wrapped logger must still write the original JSON handler's output unchanged")
	assert.Contains(t, otelOut.String(), "hello from test", "wrapped logger must also forward to the OTel log exporter")
}

func TestSetup_TracesConfigured_UsesInjectedExporter(t *testing.T) {
	clearOTLPEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:0")

	var out bytes.Buffer
	withExporterSeams(t, func(context.Context, ...autoexport.SpanOption) (trace.SpanExporter, error) {
		return stdouttrace.New(stdouttrace.WithWriter(&out))
	}, nil, nil)

	baseLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	providers, err := Setup(context.Background(), baseLogger)
	require.NoError(t, err)
	require.NoError(t, providers.Shutdown(context.Background()))
}

func TestSetup_MetricsConfigured_AddsSecondReaderOnSameProvider(t *testing.T) {
	clearOTLPEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://127.0.0.1:0")

	withExporterSeams(t, nil, func(context.Context, ...autoexport.MetricOption) (sdkmetric.Reader, error) {
		exp, err := stdoutmetric.New(stdoutmetric.WithWriter(io.Discard))
		if err != nil {
			return nil, err
		}
		return sdkmetric.NewPeriodicReader(exp), nil
	}, nil)

	baseLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	providers, err := Setup(context.Background(), baseLogger)
	require.NoError(t, err)

	// The always-on Prometheus reader must still work even with an
	// additional OTLP reader configured on the same MeterProvider.
	rec := httptest.NewRecorder()
	providers.MetricsHandler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, providers.Shutdown(context.Background()))
}

func TestSetup_ExporterConstructionFailure_ReturnsError(t *testing.T) {
	clearOTLPEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:0")

	withExporterSeams(t, func(context.Context, ...autoexport.SpanOption) (trace.SpanExporter, error) {
		return nil, assert.AnError
	}, nil, nil)

	baseLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	_, err := Setup(context.Background(), baseLogger)
	require.Error(t, err)
	assert.ErrorIs(t, err, assert.AnError)
}
