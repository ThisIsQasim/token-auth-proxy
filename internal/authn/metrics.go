package authn

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// rejectionCounter counts every request reject turns away, attributed by
// reason (the same label already used for structured logging — see
// reason's doc comment in authn.go). Generic HTTP server metrics
// (otelhttp's http.server.request.duration) can't distinguish *why* a
// 401 happened; this is the one proxy-specific signal worth adding
// deliberately.
//
// Built from otel.Meter, the global MeterProvider accessor: safe and a
// genuine no-op if telemetry.Setup was never called (keeps this package
// importable/testable standalone), and picks up the real provider
// automatically once it is — telemetry.Setup always registers one (the
// Prometheus reader is unconditional), so in production this is live
// from process start.
var rejectionCounter = mustInt64Counter(
	otel.Meter("github.com/ThisIsQasim/token-auth-proxy/internal/authn"),
	"authn.rejections",
	"Number of inbound requests rejected by authn, by reason.",
)

// mustInt64Counter panics on error, matching the OTel Go API's own
// documented behavior for instrument construction: Int64Counter only
// errors on a malformed name, which a hardcoded literal like the one
// above can never produce (the alternative — silently swallowing a
// nil/no-op counter here — would risk masking a real typo in "name" all
// the way to a metrics blind spot found at production).
func mustInt64Counter(m metric.Meter, name, description string) metric.Int64Counter {
	c, err := m.Int64Counter(name, metric.WithDescription(description), metric.WithUnit("{rejection}"))
	if err != nil {
		panic(err)
	}
	return c
}

// recordRejection increments rejectionCounter for why, tagged with ctx's
// span if one is live (same context.Context the caller already has on
// hand from the rejected request).
func recordRejection(ctx context.Context, why reason) {
	rejectionCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", string(why))))
}
