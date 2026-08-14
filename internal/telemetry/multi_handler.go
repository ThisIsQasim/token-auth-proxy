package telemetry

import (
	"context"
	"errors"
	"log/slog"
)

// multiHandler fans a record out to every one of its handlers — there's
// no stdlib equivalent. Used to keep the existing stdout JSON handler's
// exact output untouched (test/testutil.waitForListenAddr and every
// integration test parse it directly) while additionally forwarding
// every record to the OTel Logs SDK once log export is configured, via
// Setup wrapping the base logger in one of these rather than replacing
// it outright.
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(handlers ...slog.Handler) *multiHandler {
	return &multiHandler{handlers: handlers}
}

// Enabled reports true if any handler would handle a record at level —
// each handler still makes its own Enabled decision again inside
// Handle, so one handler's broader level threshold never causes a
// record to reach a narrower one that wouldn't have wanted it.
func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle dispatches record to every handler that wants it. Each gets
// its own record.Clone(): slog.Record's own doc comment requires this
// — its Attrs can only be iterated once unless cloned first — since
// handing the same Record to more than one handler is exactly what
// this type exists to do.
func (m *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, record.Level) {
			continue
		}
		if err := h.Handle(ctx, record.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: next}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: next}
}
