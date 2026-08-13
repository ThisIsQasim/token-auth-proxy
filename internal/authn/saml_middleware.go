package authn

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// serveACS dispatches an inbound ACS callback (the IdP POSTing its
// SAMLResponse back) to mw.ServeACS. A thin, directly-testable wrapper
// — mw.OnError is already samlOnError (wired once, at build time in
// buildSAMLProvider), so any parse/validation failure is bridged to
// structured logging automatically; nothing else needs to happen here.
func serveACS(mw *samlsp.Middleware, w http.ResponseWriter, r *http.Request) {
	mw.ServeACS(w, r)
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
		logger.Warn("saml request failed", fields...)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}
}

// rejectUnavailable responds 503 with a Retry-After hint when
// SAMLRegistry.Provider couldn't build or refresh a provider — distinct
// from JWT's uniform 401-for-everything (see reject in middleware.go)
// because this specifically means "the operator's configured
// idp_metadata_url is unreachable or malformed," not "your credential
// is bad." retryAfter should be the same window the registry itself
// negative-caches the failure for (SAMLRegistry.retry), so a client
// that honors Retry-After won't retry any sooner than the registry
// would actually attempt a rebuild.
func rejectUnavailable(w http.ResponseWriter, logger *slog.Logger, r *http.Request, err error, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("service unavailable"))

	logger.Warn("rejected request", "reason", string(reasonSAMLMetadataUnavailable), "path", r.URL.Path, "err", err)
}
