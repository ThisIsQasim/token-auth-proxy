package authn

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/oauth"
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
	jwtStale                          // the login cookie failed verification; nothing written, caller renews or drops it
)

// enforceJWT applies JWT verification to r using cfg/reg, writing a
// rejection response itself for jwtRejected (via reject) but leaving
// the response untouched for jwtNoCredential — that case has no
// response to write yet, since what happens next (fall through to
// SAML, or JWT's own no-credential 401) is the caller's decision, not
// this function's. Assumes cfg.Inbound.Auth.JWTEnabled(); callers must
// check that themselves before calling.
//
// A token's iss can match more than one configured source (see
// JWTSourcesByIssuer) — when it does, each is tried in turn until one
// fully verifies the token, or all of them have failed. If every
// candidate fails, the reported reason isn't simply whichever was tried
// last: a reasonKeysUnavailable failure on any candidate always wins the
// report over an ordinary verification failure on another (see the
// candidate loop below for why).
func enforceJWT(w http.ResponseWriter, r *http.Request, cfg *config.Config, reg *Registry, logger *slog.Logger) (jwtOutcome, *principal) {
	raw, loginSrc, ok := extractTokenFrom(r, cfg.Inbound.Auth)
	if !ok {
		return jwtNoCredential, nil
	}

	// A token from a browser login cookie that fails verification (expired
	// by the server's clock, signed by a rotated-out key, ...) is a session
	// to renew, not a client error: the caller drops the cookie and refreshes
	// or logs in again. A credential presented any other way is still a 401,
	// and so is a failure to fetch keys, which no new token would fix.
	stale := func(why reason) bool { return loginSrc != nil && why != reasonKeysUnavailable }

	iss, err := unverifiedIssuer(raw)
	if err != nil {
		if stale(reasonMalformedToken) {
			return jwtStale, nil
		}
		reject(w, logger, r, bearerInvalidChallenge(cfg), reasonMalformedToken)
		return jwtRejected, nil
	}
	loggedIss := truncate(iss, maxLoggedIssuerLen)

	candidates := cfg.Inbound.Auth.JWTSourcesByIssuer(iss)
	if len(candidates) == 0 {
		if stale(reasonUnknownIssuer) {
			return jwtStale, nil
		}
		reject(w, logger, r, bearerInvalidChallenge(cfg), reasonUnknownIssuer, "issuer", loggedIss)
		return jwtRejected, nil
	}

	// More than one candidate means multiple sources deliberately share
	// this issuer (see InboundAuthConfig's doc comment) - try each in
	// config order, moving on only if the previous one's entire
	// verification failed, and stopping at the first full success.
	//
	// What gets reported if every candidate fails isn't simply "the
	// last one tried": a reasonKeysUnavailable failure (the configured
	// JWKS/discovery endpoint is unreachable - an operator problem, not
	// a token problem) always wins over a routine verification failure
	// (bad signature, expired, ...) on some other candidate, and the
	// *first* source to hit it is what's kept. Without that priority, a
	// down endpoint - during exactly the JWKS/CA migration this feature
	// exists for - could go unnoticed: its Warn-level log line would
	// only ever surface when it happened to be the last candidate
	// tried, silently losing that visibility the moment a request also
	// exercises a working sibling source afterward.
	var reportReason reason
	var reportArgs []any
	var keysErr error
	haveKeysUnavailable := false
	for _, src := range candidates {
		kf, err := reg.Keyfunc(r.Context(), src)
		if err != nil {
			if !haveKeysUnavailable {
				reportReason = reasonKeysUnavailable
				reportArgs = []any{"source", src.Name, "err", err}
				keysErr = fmt.Errorf("source %q: %w", src.Name, err)
				haveKeysUnavailable = true
			}
			continue
		}

		claims, err := verify(raw, src, kf)
		if err != nil {
			if !haveKeysUnavailable {
				reportReason = classify(err)
				reportArgs = []any{"source", src.Name}
			}
			continue
		}
		// A person taken off the denylist loses a token that is still valid.
		if src.Local && reg.deniedLocalSubject(claims) {
			if !haveKeysUnavailable {
				reportReason = reasonSubjectDenied
				reportArgs = []any{"source", src.Name}
			}
			continue
		}

		return jwtAllowed, jwtPrincipal(src, claims)
	}

	if stale(reportReason) {
		return jwtStale, nil
	}
	// Not the caller's fault and nothing it can fix by sending a different
	// token: the keys could not be fetched. A 401 invalid_token would tell a
	// client to discard a perfectly good credential, so say so with a 503 and
	// when to retry, as the SAML and login legs do.
	if reportReason == reasonKeysUnavailable {
		rejectUnavailable(w, logger, r, reasonKeysUnavailable, keysErr, reg.retry)
		return jwtRejected, nil
	}
	reject(w, logger, r, bearerInvalidChallenge(cfg), reportReason, reportArgs...)
	return jwtRejected, nil
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
// Whenever a leg allows a request (steps 2 to 4, and 6), cfg.ACL then
// decides whether it is forwarded or gets a 403; with no ACL rules it
// always is. The ACS path in step 1 is never subject to ACLs.
//
// Known, deliberate gap: step 4 redirects everything without a
// session, including POSTs and JSON API calls, for which a 302 to an
// HTML login page is useless and loses the request body. There's no
// content negotiation (e.g. sniffing Accept to choose 401 vs 302) in
// this build — see the README's SAML limitations section.
func NewMiddleware(source ConfigSource, jwtReg *Registry, samlReg *SAMLRegistry, basicReg *BasicRegistry, loginReg *LoginRegistry, oauthReg *oauth.Registry, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	deps := loginDeps{saml: samlReg, basic: basicReg, login: loginReg}
	regs := authRegistries{jwt: jwtReg, saml: samlReg, basic: basicReg, login: loginReg}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := source.Current()

			jwtReg.Reconcile(cfg)
			samlReg.Reconcile(cfg)
			basicReg.Reconcile(cfg)
			if oauthReg != nil {
				oauthReg.Reconcile(cfg)
			}

			samlEnabled := cfg.Inbound.Auth.SAMLEnabled()
			loginMethodCount := cfg.Inbound.Auth.LoginMethodCount()

			var samlSrc config.SAMLSource
			if samlEnabled {
				samlSrc = *cfg.Inbound.Auth.SAML
			}

			// Step 1.
			if samlEnabled && r.URL.Path == samlSrc.ACSPath {
				mw, err := samlReg.Provider(samlSrc)
				if err != nil {
					rejectUnavailable(w, logger, r, reasonSAMLMetadataUnavailable, err, samlReg.retry)
					return
				}
				serveACSRetrying(samlReg, samlSrc, mw, w, r)
				return
			}

			// Step 1b: OIDC login callbacks and the proxy's own login
			// routes. Like the ACS path, neither can sit behind a credential
			// check: the browser arrives with none.
			for i := range cfg.Inbound.Auth.JWT {
				if src := &cfg.Inbound.Auth.JWT[i]; src.LoginEnabled() && r.URL.Path == src.Login.CallbackPath {
					loginReg.Callback(w, r, *src)
					return
				}
			}
			if loginMethodCount > 0 && isLoginRoute(r.URL.Path) {
				serveLoginRoute(w, r, cfg, deps, logger)
				return
			}
			if loginMethodCount > 0 && isLogoutRoute(r.URL.Path) {
				loginReg.serveLogout(w, r, cfg, logger)
				return
			}
			if oauthReg != nil && oauthReg.Serves(r.URL.Path) {
				serveOAuth(w, r, cfg, regs, oauthReg, logger)
				return
			}

			authenticate(w, r, cfg, regs, logger, func(p *principal, r *http.Request) {
				if authorize(w, r, cfg.ACL, p, logger) {
					next.ServeHTTP(w, r)
				}
			})
		})
	}
}

// authRegistries bundles the per-method registries authenticate consults.
type authRegistries struct {
	jwt   *Registry
	saml  *SAMLRegistry
	basic *BasicRegistry
	login *LoginRegistry
}

// authenticate runs steps 2 to 6 of NewMiddleware's precedence order and
// hands the outcome to allow: allow(p, r) is called, exactly once, when a
// leg accepts the request (or none is enabled, p == nil), with the
// principal it identified and the request to forward (SAML's carries the
// session in its context). When a leg instead writes a response of its
// own (a 401 challenge, an IdP redirect, a login page, a 503), allow is
// never called. Deciding what an accepted request is then allowed to do
// is allow's job, which keeps this reusable by routes that need to know
// who is logged in without forwarding anything.
func authenticate(w http.ResponseWriter, r *http.Request, cfg *config.Config, regs authRegistries, logger *slog.Logger, allow func(*principal, *http.Request)) {
	jwtReg, samlReg, basicReg, loginReg := regs.jwt, regs.saml, regs.basic, regs.login

	jwtEnabled := cfg.Inbound.Auth.JWTEnabled()
	samlEnabled := cfg.Inbound.Auth.SAMLEnabled()
	basicEnabled := cfg.Inbound.Auth.BasicEnabled()
	loginMethodCount := cfg.Inbound.Auth.LoginMethodCount()

	var samlSrc config.SAMLSource
	if samlEnabled {
		samlSrc = *cfg.Inbound.Auth.SAML
	}
	var basicSrc config.BasicSource
	if basicEnabled {
		basicSrc = *cfg.Inbound.Auth.Basic
	}

	// Refresh cookies are taken off the request before any leg decides,
	// so none of them can forward one to the backend.
	refreshTokens := TakeRefreshCookies(r, cfg.Inbound.Auth)

	// Step 2.
	if basicEnabled {
		outcome, username := enforceBasic(w, r, basicSrc, basicReg, logger)
		switch outcome {
		case basicAllowed:
			// Forwarded byte-for-byte unchanged, like the other
			// legs — the Authorization header included, since
			// stripping it would break a backend that does its
			// own thing with the same credential.
			allow(basicPrincipal(username), r)
			return
		case basicRejected:
			return
		case basicNoCredential:
			// Fall through to step 3/4/5 below.
		}
	}

	// Step 3.
	if jwtEnabled {
		if loginReg.Refresh(w, r, cfg, refreshTokens) {
			return
		}
		outcome, p := enforceJWT(w, r, cfg, jwtReg, logger)
		if outcome == jwtStale {
			// Drop the stale login cookie, then try to renew the session
			// with the refresh token; failing that, the request is simply
			// credential-less and falls through to login or the 401 below.
			loginReg.DropStaleLogin(w, r, cfg)
			if loginReg.Refresh(w, r, cfg, refreshTokens) {
				return
			}
			outcome, p = enforceJWT(w, r, cfg, jwtReg, logger)
		}
		switch outcome {
		case jwtAllowed:
			// Forwarded byte-for-byte unchanged: no identity
			// headers injected, no request mutation — not
			// promised anywhere in the schema, and real scope
			// creep to add here.
			allow(p, r)
			return
		case jwtRejected:
			return
		case jwtStale:
			// Unreachable: the stale cookie was dropped above, so
			// enforceJWT cannot report it again.
			reject(w, logger, r, bearerInvalidChallenge(cfg), reasonInvalidClaims)
			return
		case jwtNoCredential:
			// Fall through to step 4/5 below.
		}
	}

	// Step 4. With two or more interactive methods, a browser
	// navigation goes to the method it picked before, or to the
	// picker; with exactly one, that method runs directly.
	nav := browserNav(r)
	if loginMethodCount >= 2 && nav {
		methods := loginMethods(cfg.Inbound.Auth)
		m, ok := chosenMethod(r, methods)
		if !ok {
			redirectToPicker(w, r)
			return
		}
		switch m.kind {
		case "basic":
			serveBasicChallengePage(w, r, cfg.Inbound.Auth, logger)
			return
		case "jwt":
			src := jwtLoginSource(cfg.Inbound.Auth, m.source)
			loginReg.Start(w, r, src, r.URL.RequestURI())
			return
		}
		// "saml" runs below.
	}
	if samlEnabled {
		mw, err := samlReg.Provider(samlSrc)
		if err != nil {
			rejectUnavailable(w, logger, r, reasonSAMLMetadataUnavailable, err, samlReg.retry)
			return
		}
		enforceSAML(mw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allow(samlSessionPrincipal(r), r)
		})).ServeHTTP(w, r)
		return
	}
	if loginMethodCount == 1 && nav {
		// Only a JWT login source can be the one method here: SAML
		// returned above, and a lone Basic source falls through to
		// the 401 challenge below.
		if srcs := cfg.Inbound.Auth.LoginSources(); len(srcs) == 1 {
			loginReg.Start(w, r, srcs[0], r.URL.RequestURI())
			return
		}
	}

	// Step 5.
	if jwtEnabled || basicEnabled {
		var challenges []string
		if basicEnabled {
			challenges = append(challenges, basicChallenge(basicSrc.Realm))
		}
		if jwtEnabled {
			challenges = append(challenges, bearerChallenge(cfg))
		}
		rejectChallenges(w, logger, r, reasonNoCredential, challenges)
		return
	}

	// Step 6. No identity exists, so any ACL rule denies.
	allow(nil, r)
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
func enforceBasic(w http.ResponseWriter, r *http.Request, src config.BasicSource, reg *BasicRegistry, logger *slog.Logger) (basicOutcome, string) {
	username, password, res := extractBasic(r)
	switch res {
	case basicAbsent:
		return basicNoCredential, ""
	case basicMalformed:
		rejectChallenges(w, logger, r, reasonMalformedCredential, []string{basicChallenge(src.Realm)})
		return basicRejected, ""
	}

	ok, err := reg.Verify(src, username, password)
	if err != nil {
		// Only ever errBasicSaturated: a capacity problem, not a
		// credential one, so it gets SAML's 503 treatment rather than a
		// 401 that would tell the client its password was wrong.
		rejectUnavailable(w, logger, r, reasonBasicSaturated, err, reg.verifyTimeout)
		return basicRejected, ""
	}
	if !ok {
		rejectChallenges(w, logger, r, reasonBadCredential, []string{basicChallenge(src.Realm)},
			"user", truncate(username, maxLoggedUsernameLen))
		return basicRejected, ""
	}

	return basicAllowed, username
}

// Challenge values for the WWW-Authenticate header. Per RFC 6750 §3,
// the error parameter only belongs on a challenge answering a request
// that actually presented a credential; a request that carried none has
// no error to report, just a scheme on offer. With the OAuth server on,
// both name where its protected resource metadata is (RFC 9728), which is
// how an MCP client finds out where to log in.
func bearerChallenge(cfg *config.Config) string {
	if cfg.OAuthEnabled() {
		return fmt.Sprintf("Bearer resource_metadata=%q", cfg.Inbound.OAuthServer.ProtectedResourceMetadataURL())
	}
	return "Bearer"
}

func bearerInvalidChallenge(cfg *config.Config) string {
	c := `Bearer error="invalid_token"` // #nosec G101 -- an RFC 6750 challenge string, not a credential value
	if cfg.OAuthEnabled() {
		c += fmt.Sprintf(", resource_metadata=%q", cfg.Inbound.OAuthServer.ProtectedResourceMetadataURL())
	}
	return c
}

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
func reject(w http.ResponseWriter, logger *slog.Logger, r *http.Request, challenge string, why reason, extra ...any) {
	rejectChallenges(w, logger, r, why, []string{challenge}, extra...)
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
