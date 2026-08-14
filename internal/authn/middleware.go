package authn

import (
	"log/slog"
	"net/http"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// maxLoggedIssuerLen bounds how much of a token's (attacker-controlled,
// pre-verification) iss claim is ever written to a log field.
const maxLoggedIssuerLen = 256

// jwtOutcome is enforceJWT's tri-state result — distinguishing "no
// credential was presented at all" from "one was presented and it was
// rejected" is exactly what NewMiddleware needs to decide whether SAML
// gets a turn (see NewMiddleware's doc comment for the full precedence
// order): a presented-but-invalid bearer token is unambiguously
// API-style auth, and redirecting it to an interactive IdP login page
// would be both useless and would mask the real error, so jwtRejected
// must be final, never falling through to SAML the way jwtNoCredential
// does.
type jwtOutcome int

const (
	jwtNoCredential jwtOutcome = iota // nothing extracted; caller decides what happens next
	jwtAllowed                        // a credential was presented and verified
	jwtRejected                       // a credential was presented and failed; response already written
)

// enforceJWT applies JWT verification to r using cfg/reg, writing a
// rejection response itself for jwtRejected (via reject) but leaving
// the response untouched for jwtNoCredential — that case has no
// response to write yet, since what happens next (fall through to
// SAML, or JWT's own no-credential 401) is the caller's decision, not
// this function's. Assumes cfg.Inbound.Auth.JWTEnabled(); callers must
// check that themselves before calling.
func enforceJWT(w http.ResponseWriter, r *http.Request, cfg *config.Config, reg *Registry, logger *slog.Logger) jwtOutcome {
	raw, ok := extractToken(r, cfg.Inbound.Auth)
	if !ok {
		return jwtNoCredential
	}

	iss, err := unverifiedIssuer(raw)
	if err != nil {
		reject(w, logger, r, reasonMalformedToken, true)
		return jwtRejected
	}
	loggedIss := truncate(iss, maxLoggedIssuerLen)

	src, ok := cfg.Inbound.Auth.JWTSourceByIssuer(iss)
	if !ok {
		reject(w, logger, r, reasonUnknownIssuer, true, "issuer", loggedIss)
		return jwtRejected
	}

	kf, err := reg.Keyfunc(r.Context(), src)
	if err != nil {
		reject(w, logger, r, reasonKeysUnavailable, true, "source", src.Name, "err", err)
		return jwtRejected
	}

	if _, err := verify(raw, src, kf); err != nil {
		reject(w, logger, r, classify(err), true, "source", src.Name)
		return jwtRejected
	}

	return jwtAllowed
}

// NewMiddleware returns a middleware enforcing JWT and/or SAML
// verification on every request it wraps, reading the live config from
// source on each request exactly as proxy.New's Rewrite callback
// already does. Both registries' Reconcile are called unconditionally,
// even when their respective auth mode is disabled — that's what tears
// resolvers/providers down when the last enabled source is
// removed/disabled via hot-reload; cheap (an atomic load and a pointer
// comparison each) otherwise. Safe to install unconditionally, even at
// startup with nothing configured: a later hot-reload can add a source,
// and the fully-disabled path costs two atomic config loads per request.
//
// JWT (reject-based, 401) and SAML (redirect-based, 302) can't be two
// independently stacked middleware layers — JWT-outer would 401 a
// credential-less browser before SAML ever got a chance to redirect it;
// SAML-outer would redirect an API client's bearer token before JWT
// ever examined it. Per request, in order:
//
//  1. SAML enabled and r.URL.Path is the configured acs_path: dispatch
//     to serveACS immediately, before anything else. Non-negotiable:
//     samlsp's HandleStartAuthFlow panics if a RequireAccount-wrapped
//     handler ever sees the ACS path ("don't wrap Middleware with
//     RequireAccount"), so the ACS path must never reach step 3 below,
//     and a JWT 401 here would just break the login too.
//  2. JWT enabled and a JWT-shaped credential was extracted: JWT alone
//     decides (enforceJWT's jwtAllowed or jwtRejected). SAML is never
//     consulted for a request that presented (even a bad) bearer token.
//  3. Otherwise, if SAML is enabled: enforceSAML decides — a valid
//     session forwards, a missing/invalid one redirects to the IdP.
//     This is both the SAML-only case and the "JWT enabled but no
//     credential at all" hand-off case from step 2.
//  4. Otherwise, if JWT is enabled: today's "genuinely no credential"
//     401, unchanged from the JWT-only build.
//  5. Neither enabled: pass through untouched.
//
// Known, deliberate gap: step 3 redirects everything without a
// session, including POSTs and JSON API calls, for which a 302 to an
// HTML login page is useless and loses the request body. There's no
// content negotiation (e.g. sniffing Accept to choose 401 vs 302) in
// this build — see the README's SAML limitations section.
func NewMiddleware(source ConfigSource, jwtReg *Registry, samlReg *SAMLRegistry, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := source.Current()

			jwtReg.Reconcile(cfg)
			samlReg.Reconcile(cfg)

			jwtEnabled := cfg.Inbound.Auth.JWTEnabled()
			samlEnabled := cfg.Inbound.Auth.SAMLEnabled()

			var samlSrc config.SAMLSource
			if samlEnabled {
				samlSrc = *cfg.Inbound.Auth.SAML
			}

			// Step 1.
			if samlEnabled && r.URL.Path == samlSrc.ACSPath {
				mw, err := samlReg.Provider(samlSrc)
				if err != nil {
					rejectUnavailable(w, logger, r, err, samlReg.retry)
					return
				}
				serveACS(mw, w, r)
				return
			}

			// Step 2.
			if jwtEnabled {
				switch enforceJWT(w, r, cfg, jwtReg, logger) {
				case jwtAllowed:
					// Forwarded byte-for-byte unchanged: no identity
					// headers injected, no request mutation — not
					// promised anywhere in the schema, and real scope
					// creep to add here.
					next.ServeHTTP(w, r)
					return
				case jwtRejected:
					return
				case jwtNoCredential:
					// Fall through to step 3/4 below.
				}
			}

			// Step 3.
			if samlEnabled {
				mw, err := samlReg.Provider(samlSrc)
				if err != nil {
					rejectUnavailable(w, logger, r, err, samlReg.retry)
					return
				}
				enforceSAML(mw, next).ServeHTTP(w, r)
				return
			}

			// Step 4.
			if jwtEnabled {
				reject(w, logger, r, reasonNoCredential, false)
				return
			}

			// Step 5.
			next.ServeHTTP(w, r)
		})
	}
}

// reject writes a minimal 401 response — never detailing why, per
// reason's doc comment in authn.go — and logs the reason server-side.
// Client-fault reasons (no/bad/expired/wrong-issuer credential) are
// expected background noise (scanners, misconfigured clients) and log
// at Info; reasonKeysUnavailable is an operator-actionable problem (the
// configured JWKS/discovery endpoint is unreachable) and logs at Warn.
func reject(w http.ResponseWriter, logger *slog.Logger, r *http.Request, why reason, credentialPresent bool, extra ...any) {
	if credentialPresent {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	} else {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("unauthorized"))

	fields := append([]any{"reason", string(why), "path", r.URL.Path}, extra...)
	if why == reasonKeysUnavailable {
		logger.WarnContext(r.Context(), "rejected request", fields...)
	} else {
		logger.InfoContext(r.Context(), "rejected request", fields...)
	}
	recordRejection(r.Context(), why)
}

// truncate returns s, or its first n bytes if s is longer — used to
// bound attacker-controlled values (a token's unverified iss claim)
// before they're written to a structured log field.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
