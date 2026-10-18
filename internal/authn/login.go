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

	"golang.org/x/oauth2"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const (
	// loginStateCookie carries the in-flight authorization request
	// (state, nonce, PKCE verifier, where to return to) from the redirect
	// to the callback. Unsigned: every value in it is either compared
	// against what the IdP echoes back or only ever used by this proxy,
	// and return_to is sanitized again at the callback.
	loginStateCookie = "tap_login_state"
	loginStateTTL    = 10 * time.Minute

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
	client   *http.Client
	fp       string
	expires  time.Time
	lastErr  error
	nextTry  time.Time
}

// LoginRegistry runs the OIDC authorization code flow for JWT sources
// that have a login block. It only produces the ID token cookie; the
// token is then verified on every request by the ordinary JWT leg.
type LoginRegistry struct {
	jwt    *Registry
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*loginEndpoints

	refreshMu    sync.Mutex
	refreshCalls map[string]*refreshCall
}

// NewLoginRegistry returns a LoginRegistry that verifies ID tokens with the
// keys jwt resolves for each source.
func NewLoginRegistry(jwt *Registry, logger *slog.Logger) *LoginRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoginRegistry{jwt: jwt, logger: logger, now: time.Now, entries: map[string]*loginEndpoints{}, refreshCalls: map[string]*refreshCall{}}
}

func loginFingerprint(src config.JWTSource) string {
	return src.Issuer + "\x00" + src.OIDCDiscoveryURL + "\x00" + src.CACert
}

// endpoints returns the authorization and token endpoints for src from
// its discovery document, cached per source. A failed fetch is cached
// briefly so an unreachable IdP doesn't get a fetch per request.
func (l *LoginRegistry) endpoints(ctx context.Context, src config.JWTSource) (*loginEndpoints, error) {
	fp := loginFingerprint(src)

	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[src.Name]
	if e != nil && e.fp == fp {
		if e.lastErr == nil && l.now().Before(e.expires) {
			return e, nil
		}
		if e.lastErr != nil && l.now().Before(e.nextTry) {
			return nil, e.lastErr
		}
	}
	if e != nil && e.fp != fp && e.client != nil {
		e.client.CloseIdleConnections()
	}

	fail := func(err error) error {
		l.entries[src.Name] = &loginEndpoints{fp: fp, lastErr: err, nextTry: l.now().Add(loginRetry)}
		return err
	}

	client := &http.Client{Timeout: loginHTTPTimeout}
	if src.CACert != "" {
		c, err := newCACertClient(src.CACert)
		if err != nil {
			return nil, fail(fmt.Errorf("build ca_cert trust roots: %w", err))
		}
		client = c
	}

	fetchCtx, cancel := context.WithTimeout(ctx, loginHTTPTimeout)
	defer cancel()
	doc, err := fetchDiscovery(fetchCtx, client, src.OIDCDiscoveryURL, src.Issuer)
	if err != nil {
		client.CloseIdleConnections()
		return nil, fail(fmt.Errorf("resolve oidc discovery: %w", err))
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint} {
		if err := validateAbsoluteHTTPURL(v); err != nil {
			client.CloseIdleConnections()
			return nil, fail(fmt.Errorf("discovery document %s: %w", name, err))
		}
	}

	e = &loginEndpoints{authURL: doc.AuthorizationEndpoint, tokenURL: doc.TokenEndpoint, client: client, fp: fp, expires: l.now().Add(loginEndpointsTTL)}
	l.entries[src.Name] = e
	return e, nil
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
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the https-ness of sp_base_url, which may legitimately be http in local dev
		Name:     loginStateCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/",
		MaxAge:   int(loginStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   loginSecure(src),
		SameSite: http.SameSiteLaxMode,
	})

	authURL := l.oauthConfig(src, e).AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback completes the flow: it checks state, exchanges the code (with
// the PKCE verifier, and the client secret for a confidential client),
// verifies the ID token and its nonce, and stores the token in the
// login cookie.
func (l *LoginRegistry) Callback(w http.ResponseWriter, r *http.Request, src config.JWTSource) {
	w.Header().Set("Cache-Control", "no-store")

	c, err := r.Cookie(loginStateCookie)
	if err != nil {
		l.fail(w, r, http.StatusBadRequest, "login session expired, try again", errors.New("missing state cookie"))
		return
	}
	// Single use: cleared whatever happens below.
	http.SetCookie(w, &http.Cookie{Name: loginStateCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: loginSecure(src), SameSite: http.SameSiteLaxMode}) //nolint:gosec // see Start

	var st loginState
	if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil || json.Unmarshal(raw, &st) != nil || st.Source != src.Name {
		l.fail(w, r, http.StatusBadRequest, "login session invalid, try again", errors.New("malformed state cookie"))
		return
	}

	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 || st.State == "" {
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

	kf, err := l.jwt.Keyfunc(ctx, src)
	if err != nil {
		rejectUnavailable(w, l.logger, r, reasonKeysUnavailable, err, loginRetry)
		return
	}
	claims, err := verify(rawID, src, kf)
	if err != nil {
		l.fail(w, r, http.StatusForbidden, "login failed", fmt.Errorf("id token: %s", classify(err)))
		return
	}
	if n, _ := claims["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(st.Nonce)) != 1 {
		l.fail(w, r, http.StatusForbidden, "login failed", errors.New("id token nonce mismatch"))
		return
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		l.fail(w, r, http.StatusForbidden, "login failed", errors.New("id token has no exp"))
		return
	}
	maxAge := int(time.Until(exp.Time).Seconds())
	if maxAge <= 0 {
		l.fail(w, r, http.StatusForbidden, "login failed", errors.New("id token already expired"))
		return
	}
	if len(rawID) > maxCookieValueLen {
		l.fail(w, r, http.StatusInternalServerError, "login failed", fmt.Errorf("id token is %d bytes, too large for a cookie", len(rawID)))
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
	if u.Path == config.LoginPathPrefix || strings.HasPrefix(u.Path, config.LoginPathPrefix+"/") {
		return "/"
	}
	return u.RequestURI()
}
