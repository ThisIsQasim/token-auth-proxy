package config

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// defaultDebounce coalesces bursts of filesystem events (e.g. an editor's
// multiple write() syscalls, or a temp-file-then-rename save) into a single
// reload.
const defaultDebounce = 150 * time.Millisecond

// dirRetryBackoff is how long Watcher waits before retrying to re-add a
// watch on its config directory if that directory itself disappears.
const dirRetryBackoff = time.Second

// Watcher loads a Config from a file and keeps it live-updated as the file
// changes on disk, without requiring the caller to restart anything.
//
// The parent directory is watched, not the file itself, so that atomic
// replace-via-rename (editors, `mv`, and Kubernetes ConfigMap volume
// symlink-swaps) is picked up correctly — watching the file's inode
// directly would miss all of those. Any event in the directory triggers a
// debounced re-read of the real path, rather than trying to filter by
// filename, since a ConfigMap update's fsnotify event won't even name the
// mounted file.
//
// A reload that fails to parse or validate is logged and discarded — the
// previously published Config stays live, so a transient bad write never
// corrupts the running proxy.
type Watcher struct {
	path     string
	dir      string
	debounce time.Duration
	logger   *slog.Logger
	fsw      *fsnotify.Watcher

	current atomic.Pointer[Config]
	reloadN atomic.Int64
}

// NewWatcher loads the initial config synchronously (failing fast if it's
// invalid) and registers the underlying filesystem watch before
// returning. Establishing the watch here — rather than lazily inside
// Start — matters: the kernel buffers inotify events for a watch as soon
// as it's registered, even before anything is reading them, so a write
// that happens between NewWatcher returning and Start's event loop
// getting scheduled is still captured. If the watch were only set up
// inside Start's goroutine, a caller that writes the file immediately
// after starting the watcher in the background could lose that update
// forever.
func NewWatcher(path string, logger *slog.Logger) (*Watcher, error) {
	if logger == nil {
		logger = slog.Default()
	}

	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create file watcher: %w", err)
	}

	dir := filepath.Dir(path)
	if err := fsw.Add(dir); err != nil {
		_ = fsw.Close()
		return nil, fmt.Errorf("watch config directory %s: %w", dir, err)
	}

	w := &Watcher{
		path:     path,
		dir:      dir,
		debounce: defaultDebounce,
		logger:   logger,
		fsw:      fsw,
	}
	w.current.Store(cfg)
	return w, nil
}

// Current returns the most recently, successfully loaded Config.
func (w *Watcher) Current() *Config {
	return w.current.Load()
}

// ReloadCount reports how many times the config has been successfully
// reloaded since Start began (not counting the initial load). Exposed
// mainly for tests to assert on debounce behavior.
func (w *Watcher) ReloadCount() int64 {
	return w.reloadN.Load()
}

// Close stops watching the configuration directory. It's safe to call
// even if Start is never invoked (e.g. a caller only wants the initial
// Current() value); Start also closes the watch when ctx is canceled, so
// calling Close again afterward is harmless.
func (w *Watcher) Close() error {
	return w.fsw.Close()
}

// Start runs the watch's event loop until ctx is canceled. It blocks, so
// callers should run it in a goroutine. The underlying watch is already
// established by NewWatcher; Start only consumes events from it. A nil
// error return means ctx was canceled; anything else is a genuine
// failure.
func (w *Watcher) Start(ctx context.Context) error {
	defer func() { _ = w.fsw.Close() }()

	var timer *time.Timer
	var timerC <-chan time.Time

	resetDebounce := func() {
		if timer == nil {
			timer = time.NewTimer(w.debounce)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(w.debounce)
		}
		timerC = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-w.fsw.Events:
			if !ok {
				return nil
			}
			w.logger.Debug("config directory event", "event", event.String())
			resetDebounce()

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			w.logger.Warn("config watcher error", "err", err)

		case <-timerC:
			timerC = nil
			w.reload()

			// A removed/recreated directory (rare, but possible on some
			// bind-mount setups) drops the watch silently; make sure
			// we're still watching it.
			if err := w.fsw.Add(w.dir); err != nil {
				w.logger.Warn("failed to re-establish config directory watch, retrying", "dir", w.dir, "err", err)
				w.retryAddDir(ctx)
			}
		}
	}
}

// retryAddDir retries adding the watch directory on a fixed backoff until
// it succeeds or ctx is canceled.
func (w *Watcher) retryAddDir(ctx context.Context) {
	ticker := time.NewTicker(dirRetryBackoff)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.fsw.Add(w.dir); err != nil {
				w.logger.Warn("still unable to watch config directory", "dir", w.dir, "err", err)
				continue
			}
			w.logger.Info("re-established config directory watch", "dir", w.dir)
			return
		}
	}
}

// reload re-reads and re-validates the config file from disk. On success
// it publishes the new Config and warns if anything besides Target
// changed (those fields require a restart to take effect). On failure it
// logs and leaves the previously published Config untouched.
func (w *Watcher) reload() {
	next, err := Load(w.path)
	if err != nil {
		w.logger.Warn("config reload failed, keeping previous config", "err", err)
		return
	}

	prev := w.current.Load()
	if prev != nil && (prev.ListenAddr != next.ListenAddr || prev.Timeouts != next.Timeouts) {
		w.logger.Warn("listen_addr/timeouts changed but only target is hot-reloaded; restart the process to apply them")
	}

	w.current.Store(next)
	w.reloadN.Add(1)

	if prev == nil || prev.Target != next.Target {
		w.logger.Info("config reloaded", "target", next.Target)
	}
}
