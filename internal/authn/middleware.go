package authn

import (
	"fmt"
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
		reject(w, logger, r, reasonMalformedToken)
		return jwtRejected
	}
	loggedIss := truncate(iss, maxLoggedIssuerLen)

	src, ok := cfg.Inbound.Auth.JWTSourceByIssuer(iss)
	if !ok {
		reject(w, logger, r, reasonUnknownIssuer, "issuer", loggedIss)
		return jwtRejected
	}

	kf, err := reg.Keyfunc(r.Context(), src)
	if err != nil {
		reject(w, logger, r, reasonKeysUnavailable, "source", src.Name, "err", err)
		return jwtRejected
	}

	if _, err := verify(raw, src, kf); err != nil {
		reject(w, logger, r, classify(err), "source", src.Name)
		return jwtRejected
	}

	return jwtAllowed
}

// NewMiddleware returns a middleware enforcing Basic, JWT and/or SAML
// verification on every request it wraps, reading the live config from
// source on each request exactly as proxy.New's Rewrite callback
// already does. Every registry's Reconcile is called unconditionally,
// even when its auth mode is disabled — that's what tears
// resolvers/providers/caches down when the last enabled source is
// removed/disabled via hot-reload; cheap (an atomic load and a pointer
// comparison each) otherwise. Safe to install unconditionally, even at
// startup with nothing configured: a later hot-reload can add a source,
// and the fully-disabled path costs a few atomic config loads per
// request.
//
// The three modes can't be independently stacked middleware layers —
// JWT-outer would 401 a credential-less browser before SAML ever got a
// chance to redirect it; SAML-outer would redirect an API client's
// bearer token before JWT ever examined it. Per request, in order:
//
//  1. SAML enabled and r.URL.Path is the configured acs_path: dispatch
//     to serveACS immediately, before anything else. Non-negotiable:
//     samlsp's HandleStartAuthFlow panics if a RequireAccount-wrapped
//     handler ever sees the ACS path ("don't wrap Middleware with
//     RequireAccount"), so the ACS path must never reach step 4 below,
//     and a Basic/JWT 401 here would just break the login too.
//  2. Basic enabled and an Authorization: Basic credential was
//     presented: Basic alone decides. Ahead of JWT deliberately — a JWT
//     source configured to read the Authorization header with no prefix
//     would otherwise extract the Basic credential and reject it as a
//     malformed token. (config.InboundAuthConfig.Validate rejects that
//     combination outright, so this ordering is belt-and-braces rather
//     than the only defense.) One consequence worth knowing: a client
//     that sends a Basic header *and* a JWT elsewhere (cookie, query)
//     is judged on the Basic credential alone.
//  3. JWT enabled and a JWT-shaped credential was extracted: JWT alone
//     decides (enforceJWT's jwtAllowed or jwtRejected). SAML is never
//     consulted for a request that presented (even a bad) bearer token.
//  4. Otherwise, if SAML is enabled: enforceSAML decides — a valid
//     session forwards, a missing/invalid one redirects to the IdP.
//     This is both the SAML-only case and the "Basic/JWT enabled but no
//     credential at all" hand-off case from steps 2 and 3. Note this
//     returns before step 5, so with SAML enabled a credential-less
//     request is redirected and never sees a Basic challenge: Basic
//     then only serves clients that send the header proactively, with
//     no browser password prompt.
//  5. Otherwise, if Basic and/or JWT is enabled: the "genuinely no
//     credential" 401, carrying a challenge for each enabled mode.
//  6. Nothing enabled: pass through untouched.
//
// Known, deliberate gap: step 4 redirects everything without a
// session, including POSTs and JSON API calls, for which a 302 to an
// HTML login page is useless and loses the request body. There's no
// content negotiation (e.g. sniffing Accept to choose 401 vs 302) in
// this build — see the README's SAML limitations section.
func NewMiddleware(source ConfigSource, jwtReg *Registry, samlReg *SAMLRegistry, basicReg *BasicRegistry, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := source.Current()

			jwtReg.Reconcile(cfg)
			samlReg.Reconcile(cfg)
			basicReg.Reconcile(cfg)

			jwtEnabled := cfg.Inbound.Auth.JWTEnabled()
			samlEnabled := cfg.Inbound.Auth.SAMLEnabled()
			basicEnabled := cfg.Inbound.Auth.BasicEnabled()

			var samlSrc config.SAMLSource
			if samlEnabled {
				samlSrc = *cfg.Inbound.Auth.SAML
			}
			var basicSrc config.BasicSource
			if basicEnabled {
				basicSrc = *cfg.Inbound.Auth.Basic
			}

			// Step 1.
			if samlEnabled && r.URL.Path == samlSrc.ACSPath {
				mw, err := samlReg.Provider(samlSrc)
				if err != nil {
					rejectUnavailable(w, logger, r, reasonSAMLMetadataUnavailable, err, samlReg.retry)
					return
				}
				serveACS(mw, w, r)
				return
			}

			// Step 2.
			if basicEnabled {
				switch enforceBasic(w, r, basicSrc, basicReg, logger) {
				case basicAllowed:
					// Forwarded byte-for-byte unchanged, like the other
					// legs — the Authorization header included, since
					// stripping it would break a backend that does its
					// own thing with the same credential.
					next.ServeHTTP(w, r)
					return
				case basicRejected:
					return
				case basicNoCredential:
					// Fall through to step 3/4/5 below.
				}
			}

			// Step 3.
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
					// Fall through to step 4/5 below.
				}
			}

			// Step 4.
			if samlEnabled {
				mw, err := samlReg.Provider(samlSrc)
				if err != nil {
					rejectUnavailable(w, logger, r, reasonSAMLMetadataUnavailable, err, samlReg.retry)
					return
				}
				enforceSAML(mw, next).ServeHTTP(w, r)
				return
			}

			// Step 5.
			if jwtEnabled || basicEnabled {
				var challenges []string
				if basicEnabled {
					challenges = append(challenges, basicChallenge(basicSrc.Realm))
				}
				if jwtEnabled {
					challenges = append(challenges, bearerChallenge)
				}
				rejectChallenges(w, logger, r, reasonNoCredential, challenges)
				return
			}

			// Step 6.
			next.ServeHTTP(w, r)
		})
	}
}

// basicOutcome is enforceBasic's tri-state result, mirroring
// jwtOutcome: "no credential presented" has to stay distinct from
// "presented and rejected" so NewMiddleware can decide whether another
// leg still gets a turn (see its doc comment).
type basicOutcome int

const (
	basicNoCredential basicOutcome = iota // nothing extracted; caller decides what happens next
	basicAllowed                          // a credential was presented and verified
	basicRejected                         // a credential was presented and failed; response already written
)

// enforceBasic applies Basic verification to r, writing the rejection
// response itself for basicRejected but leaving the response untouched
// for basicNoCredential — that case's outcome (fall through to JWT or
// SAML, or the combined no-credential 401) is the caller's decision.
// Assumes cfg.Inbound.Auth.BasicEnabled(); callers must check that
// themselves before calling.
func enforceBasic(w http.ResponseWriter, r *http.Request, src config.BasicSource, reg *BasicRegistry, logger *slog.Logger) basicOutcome {
	username, password, res := extractBasic(r)
	switch res {
	case basicAbsent:
		return basicNoCredential
	case basicMalformed:
		rejectChallenges(w, logger, r, reasonMalformedCredential, []string{basicChallenge(src.Realm)})
		return basicRejected
	}

	ok, err := reg.Verify(src, username, password)
	if err != nil {
		// Only ever errBasicSaturated: a capacity problem, not a
		// credential one, so it gets SAML's 503 treatment rather than a
		// 401 that would tell the client its password was wrong.
		rejectUnavailable(w, logger, r, reasonBasicSaturated, err, reg.verifyTimeout)
		return basicRejected
	}
	if !ok {
		rejectChallenges(w, logger, r, reasonBadCredential, []string{basicChallenge(src.Realm)},
			"user", truncate(username, maxLoggedUsernameLen))
		return basicRejected
	}

	return basicAllowed
}

// Challenge values for the WWW-Authenticate header. Per RFC 6750 §3,
// the error parameter only belongs on a challenge answering a request
// that actually presented a credential; a request that carried none has
// no error to report, just a scheme on offer.
const (
	bearerChallenge        = "Bearer"
	bearerInvalidChallenge = `Bearer error="invalid_token"` // #nosec G101 -- an RFC 6750 challenge string, not a credential value
)

// basicChallenge builds the WWW-Authenticate value for the Basic leg.
// realm is safe to quote directly: config.validateRealm has already
// rejected quotes, backslashes and control characters. charset is
// advertised per RFC 7617 §2.1 so a client knows to send non-ASCII
// passwords as UTF-8.
func basicChallenge(realm string) string {
	return fmt.Sprintf("Basic realm=%q, charset=%q", realm, "UTF-8")
}

// reject writes a 401 for a bearer token that was presented and failed
// — the JWT leg's only rejection shape, since its no-credential case is
// handled by NewMiddleware's combined challenge instead.
func reject(w http.ResponseWriter, logger *slog.Logger, r *http.Request, why reason, extra ...any) {
	rejectChallenges(w, logger, r, why, []string{bearerInvalidChallenge}, extra...)
}

// rejectChallenges writes a minimal 401 response — never detailing why,
// per reason's doc comment in authn.go — and logs the reason
// server-side. Client-fault reasons (no/bad/expired/wrong-issuer
// credential) are expected background noise (scanners, misconfigured
// clients) and log at Info; reasonKeysUnavailable is an
// operator-actionable problem (the configured JWKS/discovery endpoint
// is unreachable) and logs at Warn.
//
// challenges is a list because a 401 may legitimately offer more than
// one scheme (RFC 7235 §4.1) — with Basic and JWT both enabled, a
// credential-less request is genuinely answerable by either. They're
// written as separate header lines rather than one comma-joined value:
// both are legal, but Basic's realm parameter is itself
// comma-adjacent, and separate lines are what clients parse most
// reliably.
func rejectChallenges(w http.ResponseWriter, logger *slog.Logger, r *http.Request, why reason, challenges []string, extra ...any) {
	for _, c := range challenges {
		w.Header().Add("WWW-Authenticate", c)
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
