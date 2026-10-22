package authn

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const (
	// loginStateCookie prefixes the cookies carrying the in-flight authorization request
	// (state, nonce, PKCE verifier, where to return to) from the redirect
	// to the callback. Unsigned: every value in it is either compared
	// against what the IdP echoes back or only ever used by this proxy,
	// and return_to is sanitized again at the callback.
	loginStateCookie = "tap_login_state"
	loginStateTTL    = 10 * time.Minute

	// loginStateKeyLen is how many leading characters of the state value
	// name its cookie (see loginStateCookieName).
	loginStateKeyLen = 12

	// loginEndpointsTTL bounds how long a discovery result is reused;
	// loginRetry is the negative-cache window after a failed fetch.
	loginEndpointsTTL = 1 * time.Hour
	loginRetry        = 30 * time.Second
	loginHTTPTimeout  = 15 * time.Second

	// maxCookieValueLen is the largest ID token stored. Browsers drop
	// cookies over about 4096 bytes including name and attributes.
	maxCookieValueLen = 3900
)

// loginState is the payload of loginStateCookie.
type loginState struct {
	Source   string `json:"s"`
	State    string `json:"st"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
}

type loginEndpoints struct {
	authURL  string
	tokenURL string
	// endSessionURL is the provider's end_session_endpoint, empty when it
	// advertises none or an unusable one.
	endSessionURL string
	client        *http.Client
	expires       time.Time
}

// loginSlot is one source's discovery cache. Its own mutex is held across
// the fetch, so concurrent callers for the same source share one fetch
// while other sources are never blocked by it.
type loginSlot struct {
	mu      sync.Mutex
	fp      string
	good    *loginEndpoints // last successful fetch; kept serving if a refetch fails
	failErr error
	nextTry time.Time
}

// LoginRegistry runs the OIDC authorization code flow for JWT sources
// that have a login block. It only produces the ID token cookie; the
// token is then verified on every request by the ordinary JWT leg.
type LoginRegistry struct {
	jwt    *Registry
	logger *slog.Logger
	now    func() time.Time

	mu    sync.Mutex
	slots map[string]*loginSlot

	refreshMu    sync.Mutex
	refreshCalls map[string]*refreshCall
}

// NewLoginRegistry returns a LoginRegistry that verifies ID tokens with the
// keys jwt resolves for each source.
func NewLoginRegistry(jwt *Registry, logger *slog.Logger) *LoginRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoginRegistry{jwt: jwt, logger: logger, now: time.Now, slots: map[string]*loginSlot{}, refreshCalls: map[string]*refreshCall{}}
}

func loginFingerprint(src config.JWTSource) string {
	return src.Issuer + "\x00" + src.OIDCDiscoveryURL + "\x00" + src.CACert
}

// endpoints returns the authorization and token endpoints for src from
// its discovery document, cached per source. A failed fetch is cached
// briefly so an unreachable IdP doesn't get a fetch per request, and if
// an earlier fetch succeeded its result keeps being served meanwhile:
// endpoints almost never change, so a blip at the TTL boundary must not
// break logins.
func (l *LoginRegistry) endpoints(ctx context.Context, src config.JWTSource) (*loginEndpoints, error) {
	fp := loginFingerprint(src)

	l.mu.Lock()
	slot := l.slots[src.Name]
	if slot == nil {
		slot = &loginSlot{}
		l.slots[src.Name] = slot
	}
	l.mu.Unlock()

	slot.mu.Lock()
	defer slot.mu.Unlock()

	if slot.fp != fp {
		if slot.good != nil {
			slot.good.client.CloseIdleConnections()
		}
		slot.fp, slot.good, slot.failErr, slot.nextTry = fp, nil, nil, time.Time{}
	}
	if slot.good != nil && l.now().Before(slot.good.expires) {
		return slot.good, nil
	}
	if slot.failErr != nil && l.now().Before(slot.nextTry) {
		if slot.good != nil {
			return slot.good, nil
		}
		return nil, slot.failErr
	}

	e, err := l.fetchEndpoints(ctx, src)
	if err != nil {
		slot.failErr, slot.nextTry = err, l.now().Add(loginRetry)
		if slot.good != nil {
			l.logger.WarnContext(ctx, "oidc discovery refresh failed, serving the previous endpoints", "source", src.Name, "err", err)
			return slot.good, nil
		}
		return nil, err
	}
	if slot.good != nil {
		slot.good.client.CloseIdleConnections()
	}
	slot.good, slot.failErr = e, nil
	return e, nil
}

// fetchEndpoints fetches src's discovery document. Its context is
// detached from the request that happened to trigger it: the result is
// shared, so one client hanging up must not fail (and negative-cache) the
// fetch for everyone else.
func (l *LoginRegistry) fetchEndpoints(ctx context.Context, src config.JWTSource) (*loginEndpoints, error) {
	client := &http.Client{Timeout: loginHTTPTimeout}
	if src.CACert != "" {
		c, err := newCACertClient(src.CACert)
		if err != nil {
			return nil, fmt.Errorf("build ca_cert trust roots: %w", err)
		}
		client = c
	}

	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginHTTPTimeout)
	defer cancel()
	doc, err := fetchDiscovery(fetchCtx, client, src.OIDCDiscoveryURL, src.Issuer)
	if err != nil {
		client.CloseIdleConnections()
		return nil, fmt.Errorf("resolve oidc discovery: %w", err)
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint} {
		if err := validateAbsoluteHTTPURL(v); err != nil {
			client.CloseIdleConnections()
			return nil, fmt.Errorf("discovery document %s: %w", name, err)
		}
	}
	endSession := doc.EndSessionEndpoint
	if validateAbsoluteHTTPURL(endSession) != nil {
		endSession = ""
	}
	return &loginEndpoints{authURL: doc.AuthorizationEndpoint, tokenURL: doc.TokenEndpoint, endSessionURL: endSession, client: client, expires: l.now().Add(loginEndpointsTTL)}, nil
}

func (l *LoginRegistry) oauthConfig(src config.JWTSource, e *loginEndpoints) *oauth2.Config {
	lg := src.Login
	style := oauth2.AuthStyleInParams
	if lg.ClientSecret != "" && lg.TokenAuthMethod == config.TokenAuthBasic {
		style = oauth2.AuthStyleInHeader
	}
	return &oauth2.Config{
		ClientID:     lg.ClientID,
		ClientSecret: lg.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: e.authURL, TokenURL: e.tokenURL, AuthStyle: style},
		RedirectURL:  strings.TrimRight(lg.SPBaseURL, "/") + lg.CallbackPath,
		Scopes:       lg.Scopes,
	}
}

func loginSecure(src config.JWTSource) bool {
	return strings.HasPrefix(strings.ToLower(src.Login.SPBaseURL), "https://")
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loginCookie builds a cookie with the attributes every cookie this proxy
// sets shares. A negative maxAge deletes it.
func loginCookie(src config.JWTSource, name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure follows the https-ness of sp_base_url, which may legitimately be http in local dev
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   loginSecure(src),
		SameSite: http.SameSiteLaxMode,
	}
}

// loginStateCookieName keys the in-flight state cookie by the first
// characters of the state value, so two logins started in the same
// browser (two tabs) don't overwrite each other's.
func loginStateCookieName(state string) string {
	return loginStateCookie + "_" + state[:loginStateKeyLen]
}

// Start redirects the browser to src's IdP, remembering returnTo.
func (l *LoginRegistry) Start(w http.ResponseWriter, r *http.Request, src config.JWTSource, returnTo string) {
	e, err := l.endpoints(r.Context(), src)
	if err != nil {
		rejectUnavailable(w, l.logger, r, reasonLoginUnavailable, err, loginRetry)
		return
	}

	state, err1 := randomToken()
	nonce, err2 := randomToken()
	if err := errors.Join(err1, err2); err != nil {
		l.fail(w, r, http.StatusInternalServerError, "login failed", err)
		return
	}
	verifier := oauth2.GenerateVerifier()

	raw, _ := json.Marshal(loginState{Source: src.Name, State: state, Nonce: nonce, Verifier: verifier, ReturnTo: sanitizeReturnTo(returnTo)})
	http.SetCookie(w, loginCookie(src, loginStateCookieName(state), base64.RawURLEncoding.EncodeToString(raw), int(loginStateTTL.Seconds())))

	authURL := l.oauthConfig(src, e).AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

// errKeysUnavailable marks a token that could not be checked because the
// source's signing keys could not be fetched, as opposed to one that
// failed the check.
var errKeysUnavailable = errors.New("signing keys unavailable")

// verifyIDToken verifies raw under src's policy and returns its claims
// and the cookie lifetime it allows. It is the one place both the login
// callback and the refresh path decide whether an ID token is usable as
// a session.
func (l *LoginRegistry) verifyIDToken(ctx context.Context, src config.JWTSource, raw string) (jwt.MapClaims, int, error) {
	kf, err := l.jwt.Keyfunc(ctx, src)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errKeysUnavailable, err)
	}
	claims, err := verify(raw, src, kf)
	if err != nil {
		return nil, 0, fmt.Errorf("id token: %s", classify(err))
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, 0, errors.New("id token has no exp")
	}
	maxAge := int(time.Until(exp.Time).Seconds())
	if maxAge <= 0 {
		return nil, 0, errors.New("id token already expired")
	}
	if len(raw) > maxCookieValueLen {
		return nil, 0, fmt.Errorf("id token is %d bytes, too large for a cookie", len(raw))
	}
	return claims, maxAge, nil
}

// Callback completes the flow: it checks state, exchanges the code (with
// the PKCE verifier, and the client secret for a confidential client),
// verifies the ID token and its nonce, and stores the token in the
// login cookie.
func (l *LoginRegistry) Callback(w http.ResponseWriter, r *http.Request, src config.JWTSource) {
	w.Header().Set("Cache-Control", "no-store")

	q := r.URL.Query()
	stateParam := q.Get("state")
	if len(stateParam) < loginStateKeyLen {
		l.fail(w, r, http.StatusBadRequest, "login session invalid, try again", errors.New("missing or short state"))
		return
	}
	cookieName := loginStateCookieName(stateParam)
	c, err := r.Cookie(cookieName)
	if err != nil {
		l.fail(w, r, http.StatusBadRequest, "login session expired, try again", errors.New("missing state cookie"))
		return
	}
	// Single use: cleared whatever happens below.
	http.SetCookie(w, loginCookie(src, cookieName, "", -1))

	var st loginState
	if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil || json.Unmarshal(raw, &st) != nil || st.Source != src.Name {
		l.fail(w, r, http.StatusBadRequest, "login session invalid, try again", errors.New("malformed state cookie"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(stateParam), []byte(st.State)) != 1 || st.State == "" {
		l.fail(w, r, http.StatusBadRequest, "login session invalid, try again", errors.New("state mismatch"))
		return
	}
	if e := q.Get("error"); e != "" {
		l.fail(w, r, http.StatusForbidden, "login was not completed", fmt.Errorf("idp error %q: %s", e, truncate(q.Get("error_description"), 256)))
		return
	}
	code := q.Get("code")
	if code == "" {
		l.fail(w, r, http.StatusBadRequest, "login failed", errors.New("missing code"))
		return
	}

	e, err := l.endpoints(r.Context(), src)
	if err != nil {
		rejectUnavailable(w, l.logger, r, reasonLoginUnavailable, err, loginRetry)
		return
	}

	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, e.client), loginHTTPTimeout)
	defer cancel()
	tok, err := l.oauthConfig(src, e).Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		l.fail(w, r, http.StatusBadGateway, "login failed", fmt.Errorf("code exchange: %w", err))
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		l.fail(w, r, http.StatusBadGateway, "login failed", errors.New("token response has no id_token"))
		return
	}

	claims, maxAge, err := l.verifyIDToken(ctx, src, rawID)
	if errors.Is(err, errKeysUnavailable) {
		rejectUnavailable(w, l.logger, r, reasonKeysUnavailable, err, loginRetry)
		return
	}
	if err != nil {
		l.fail(w, r, http.StatusForbidden, "login failed", err)
		return
	}
	if n, _ := claims["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(st.Nonce)) != 1 {
		l.fail(w, r, http.StatusForbidden, "login failed", errors.New("id token nonce mismatch"))
		return
	}

	l.setSession(w, r, src, rawID, maxAge, tok.RefreshToken)
	http.Redirect(w, r, sanitizeReturnTo(st.ReturnTo), http.StatusFound)
}

// fail writes a terse plain-text error and logs the detail server-side.
func (l *LoginRegistry) fail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	l.logger.WarnContext(r.Context(), "oidc login failed", "path", r.URL.Path, "err", err)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// sanitizeReturnTo reduces raw to a same-origin relative reference, or
// "/" if it is anything else, so a login link can't be turned into an
// open redirect. Proxy-owned routes are rejected too, which also stops
// a picker round trip from returning to itself.
func sanitizeReturnTo(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	if u.Path == config.LogoutPath {
		return "/"
	}
	if u.Path == config.LoginPathPrefix || strings.HasPrefix(u.Path, config.LoginPathPrefix+"/") {
		return "/"
	}
	return u.RequestURI()
}
