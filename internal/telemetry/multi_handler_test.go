package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiHandler_FansOutToAllHandlers(t *testing.T) {
	var bufA, bufB bytes.Buffer
	h := newMultiHandler(
		slog.NewJSONHandler(&bufA, nil),
		slog.NewJSONHandler(&bufB, nil),
	)
	logger := slog.New(h)

	logger.Info("hello", "key", "value")

	assert.Contains(t, bufA.String(), `"msg":"hello"`)
	assert.Contains(t, bufA.String(), `"key":"value"`)
	assert.Contains(t, bufB.String(), `"msg":"hello"`)
	assert.Contains(t, bufB.String(), `"key":"value"`)
}

func TestMultiHandler_Enabled_TrueIfAnyHandlerWants(t *testing.T) {
	narrow := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})
	broad := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := newMultiHandler(narrow, broad)

	assert.True(t, h.Enabled(context.Background(), slog.LevelDebug), "broad handler wants debug, so multiHandler should too")
	assert.True(t, h.Enabled(context.Background(), slog.LevelError))

	onlyNarrow := newMultiHandler(narrow)
	assert.False(t, onlyNarrow.Enabled(context.Background(), slog.LevelDebug))
}

func TestMultiHandler_RespectsEachHandlersOwnLevel(t *testing.T) {
	var bufNarrow, bufBroad bytes.Buffer
	narrow := slog.NewJSONHandler(&bufNarrow, &slog.HandlerOptions{Level: slog.LevelError})
	broad := slog.NewJSONHandler(&bufBroad, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(newMultiHandler(narrow, broad))

	logger.Debug("debug message")

	assert.Empty(t, bufNarrow.String(), "the narrower handler must not receive a record below its own level")
	assert.Contains(t, bufBroad.String(), "debug message")
}

func TestMultiHandler_WithAttrsAppliesToAllHandlers(t *testing.T) {
	var bufA, bufB bytes.Buffer
	h := newMultiHandler(
		slog.NewJSONHandler(&bufA, nil),
		slog.NewJSONHandler(&bufB, nil),
	)
	logger := slog.New(h).With("shared", "attr")

	logger.Info("hello")

	assert.Contains(t, bufA.String(), `"shared":"attr"`)
	assert.Contains(t, bufB.String(), `"shared":"attr"`)
}

func TestMultiHandler_WithGroupAppliesToAllHandlers(t *testing.T) {
	var bufA, bufB bytes.Buffer
	h := newMultiHandler(
		slog.NewJSONHandler(&bufA, nil),
		slog.NewJSONHandler(&bufB, nil),
	)
	logger := slog.New(h).WithGroup("g").With("k", "v")

	logger.Info("hello")

	assert.Contains(t, bufA.String(), `"g":{"k":"v"}`)
	assert.Contains(t, bufB.String(), `"g":{"k":"v"}`)
}

// erroringHandler always fails Handle, letting the errors.Join
// aggregation path in multiHandler.Handle be exercised directly.
type erroringHandler struct {
	err error
}

func (e erroringHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (e erroringHandler) Handle(context.Context, slog.Record) error { return e.err }
func (e erroringHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return e }
func (e erroringHandler) WithGroup(name string) slog.Handler        { return e }

func TestMultiHandler_Handle_AggregatesErrorsFromAllHandlers(t *testing.T) {
	errA := assert.AnError
	h := newMultiHandler(erroringHandler{err: errA}, slog.NewJSONHandler(&bytes.Buffer{}, nil))

	// slog.Logger.Info swallows Handle's error, so call Handle directly
	// to assert on it.
	rec := slog.NewRecord(time.Time{}, slog.LevelInfo, "msg", 0)
	err := h.Handle(context.Background(), rec)
	require.Error(t, err)
	assert.ErrorIs(t, err, errA)
}
