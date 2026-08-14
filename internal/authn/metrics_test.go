package authn

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// testMetricReader is the one ManualReader every rejection-metric test
// in this package reads from — see TestMain. It has to be exactly one:
// the OTel Go API's global instrument delegation (internal/global.meter
// .setDelegate) is documented "guaranteed by the caller to happen only
// once" — rejectionCounter (metrics.go) is created once at package init
// against the global no-op provider, and whichever otel.SetMeterProvider
// call happens first in the test binary is the only one that ever
// actually rebinds it; every later otel.SetMeterProvider call is a
// no-op as far as that already-created instrument is concerned. Two
// tests each standing up their own ManualReader would make whichever
// one runs second silently observe nothing.
var testMetricReader *sdkmetric.ManualReader

func TestMain(m *testing.M) {
	testMetricReader = sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(testMetricReader)))
	os.Exit(m.Run())
}

// rejectionCountByReason returns authn.rejections' current cumulative
// value for reason via testMetricReader. Tests diff a before/after
// snapshot rather than asserting an absolute value, since the reader
// and counter are shared across every test in the package (see
// testMetricReader's doc comment) and cumulative temporality means
// Collect always returns the running total, not a per-call delta.
func rejectionCountByReason(t *testing.T, why reason) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, testMetricReader.Collect(t.Context(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "authn.rejections" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "authn.rejections should be a Sum aggregation (Int64Counter)")
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value(attribute.Key("reason")); ok && v.AsString() == string(why) {
					return dp.Value
				}
			}
		}
	}
	return 0
}

func TestRecordRejection_IncrementsCounterByReason(t *testing.T) {
	beforeNoCred := rejectionCountByReason(t, reasonNoCredential)
	beforeExpired := rejectionCountByReason(t, reasonExpired)

	recordRejection(context.Background(), reasonNoCredential)
	recordRejection(context.Background(), reasonNoCredential)
	recordRejection(context.Background(), reasonExpired)

	require.Equal(t, beforeNoCred+2, rejectionCountByReason(t, reasonNoCredential))
	require.Equal(t, beforeExpired+1, rejectionCountByReason(t, reasonExpired))
}
