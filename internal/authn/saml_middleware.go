package authn

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// serveACS dispatches an inbound ACS callback (the IdP POSTing its
// SAMLResponse back) to mw.ServeACS. A thin, directly-testable wrapper
// — mw.OnError is already samlOnError (wired once, at build time in
// buildSAMLProvider), so any parse/validation failure is bridged to
// structured logging automatically; nothing else needs to happen here.
func serveACS(mw *samlsp.Middleware, w http.ResponseWriter, r *http.Request) {
	mw.ServeACS(w, r)
}

// maxACSBodyBytes matches net/http's own cap on a form POST.
const maxACSBodyBytes = 10 << 20

// serveACSRetrying is serveACS with one second chance: a callback that
// fails (403) may only have failed because the IdP rotated its signing key
// or renewed its certificate since the metadata was cached, so the registry
// is asked to refetch it and the same POST is validated again against the
// fresh provider. The first attempt's response is held back until then, so
// the browser only ever sees the final outcome. The refetch is
// rate-limited by SAMLRegistry.RefreshNow, so this adds at most one IdP
// fetch a minute however many bad callbacks arrive.
func serveACSRetrying(reg *SAMLRegistry, src config.SAMLSource, mw *samlsp.Middleware, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxACSBodyBytes))
	if err != nil {
		mw.OnError(w, r, err)
		return
	}
	attempt := func(m *samlsp.Middleware) *bufferedResponse {
		buf := newBufferedResponse()
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(bytes.NewReader(body))
		r2.ContentLength = int64(len(body))
		m.ServeACS(buf, r2)
		return buf
	}

	result := attempt(mw)
	if result.status == http.StatusForbidden {
		if fresh, ok := reg.RefreshNow(src); ok {
			result = attempt(fresh)
		}
	}
	result.writeTo(w)
}

// bufferedResponse is an http.ResponseWriter that holds the response so a
// caller can decide whether to send it.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: http.Header{}, status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) WriteHeader(code int)        { b.status = code }

func (b *bufferedResponse) writeTo(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// enforceSAML requires a valid SAML session for the request, via
// mw.RequireAccount: a missing or invalid session cookie redirects to
// the IdP (SP-initiated login) rather than rejecting outright — an
// invalid session (tampered, expired, wrong secret) is indistinguishable
// from no session at all here, because samlsp.CookieSessionProvider.
// GetSession maps every samlSessionCodec.Decode failure to the same
// samlsp.ErrNoSession (see saml_session.go's Decode doc comment), so
// RequireAccount always redirects rather than ever calling mw.OnError
// for a bad session specifically — only a genuine internal error (e.g.
// failing to write the tracker cookie) reaches OnError from this path.
// A valid session forwards to next byte-for-byte unchanged, same as
// NewMiddleware's JWT leg: no identity headers injected, no request
// mutation.
func enforceSAML(mw *samlsp.Middleware, next http.Handler) http.Handler {
	return mw.RequireAccount(next)
}

// samlOnError bridges samlsp's error callback (invoked for a malformed/
// invalid ACS POST, or an internal failure writing a tracking cookie)
// to structured slog logging — mirrors reject's "log-only, never leak
// why" rule from middleware.go: assertion parsing/validation failures
// can carry attacker-influenced detail (raw XML fragments, signature
// errors), so only a bare 403 goes to the client. Logged at Warn
// uniformly rather than JWT's client-fault-vs-operator-fault split:
// unlike the bearer-token path (hit on every request, so scanner noise
// at Info keeps logs usable), the ACS callback is only ever hit once
// per login attempt, so the added visibility is worth it and the
// volume risk isn't there.
func samlOnError(logger *slog.Logger) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		fields := []any{"path", r.URL.Path, "err", err}
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			fields = append(fields, "private_err", ire.PrivateErr)
		}
		logger.WarnContext(r.Context(), "saml request failed", fields...)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}
}

// rejectUnavailable responds 503 with a Retry-After hint for a failure
// that isn't the caller's fault — distinct from JWT's and Basic's
// uniform 401-for-everything (see reject in middleware.go) because
// these mean "this proxy currently can't verify anything," not "your
// credential is bad." Two things use it: SAMLRegistry.Provider failing
// to build or refresh a provider (the configured idp_metadata_url is
// unreachable or malformed), and Basic verification being saturated
// (see BasicRegistry.sem). retryAfter should be the window the caller
// would actually have to wait — the registry's own negative-cache
// duration for SAML — so a client honoring it doesn't retry sooner
// than the answer could possibly change.
func rejectUnavailable(w http.ResponseWriter, logger *slog.Logger, r *http.Request, why reason, err error, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("service unavailable"))

	logger.WarnContext(r.Context(), "rejected request", "reason", string(why), "path", r.URL.Path, "err", err)
	recordRejection(r.Context(), why)
}
