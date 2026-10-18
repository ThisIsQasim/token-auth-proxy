package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// refreshGrace is how long a successful refresh is remembered, keyed by
// the refresh token that was redeemed. Browsers fire parallel requests,
// and several can arrive carrying the same just-expired session before
// any of them has seen the new cookies; with a rotating IdP only the
// first redemption of a refresh token is valid (and a second one may
// revoke the whole grant), so the others must reuse the first result.
// The window is per process: with several replicas behind a load
// balancer without stickiness, a rotating IdP can still see a reuse.
const refreshGrace = 30 * time.Second

type refreshOutcome struct {
	idToken      string
	refreshToken string
	maxAge       int
}

// refreshCall is one in-flight or recently finished redemption.
type refreshCall struct {
	done     chan struct{}
	out      refreshOutcome
	err      error
	finished time.Time
}

// errRefreshRejected means the IdP refused the refresh token (revoked,
// expired, rotated away), as opposed to being unreachable. The caller
// sends the user through a full login.
var errRefreshRejected = errors.New("refresh token rejected")

// setSession stores the ID token cookie and, when refresh is on and the
// IdP issued one, the refresh token cookie.
func (l *LoginRegistry) setSession(w http.ResponseWriter, r *http.Request, src config.JWTSource, idToken string, maxAge int, refreshToken string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see Start
		Name:     src.Login.CookieName,
		Value:    idToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   loginSecure(src),
		SameSite: http.SameSiteLaxMode,
	})
	if !src.Login.Refresh {
		return
	}
	if refreshToken == "" {
		l.logger.WarnContext(r.Context(), "login.refresh is on but the IdP issued no refresh token; the session will end when the ID token expires (add the offline_access scope?)", "source", src.Name)
		return
	}
	if len(refreshToken) > maxCookieValueLen {
		l.logger.WarnContext(r.Context(), "refresh token too large for a cookie, not stored", "source", src.Name, "bytes", len(refreshToken))
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see Start
		Name:     src.Login.RefreshCookieName(),
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   int(src.Login.RefreshMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   loginSecure(src),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, src config.JWTSource, name string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see Start
		Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: loginSecure(src), SameSite: http.SameSiteLaxMode,
	})
}

// Refresh renews the session of a request that carries a refresh cookie
// but no credential at all (the ID token cookie has expired and been
// dropped by the browser). On success the new cookies are set on the
// response and the new ID token is added to r, so the request goes on
// through the ordinary JWT leg as if it had never expired. The refresh
// cookies are always removed from r so they never reach the backend.
//
// It reports whether it wrote a response (the IdP was unreachable), in
// which case the caller must stop.
func (l *LoginRegistry) Refresh(w http.ResponseWriter, r *http.Request, cfg *config.Config) (responded bool) {
	var srcs []config.JWTSource
	for _, s := range cfg.Inbound.Auth.LoginSources() {
		if s.Login.Refresh {
			srcs = append(srcs, s)
		}
	}
	if len(srcs) == 0 {
		return false
	}
	defer stripRefreshCookies(r, srcs)

	if _, ok := extractToken(r, cfg.Inbound.Auth); ok {
		return false
	}

	for _, src := range srcs {
		c, err := r.Cookie(src.Login.RefreshCookieName())
		if err != nil || c.Value == "" {
			continue
		}
		out, err := l.redeem(r.Context(), src, c.Value)
		switch {
		case err == nil:
			l.setSession(w, r, src, out.idToken, out.maxAge, out.refreshToken)
			r.AddCookie(&http.Cookie{Name: src.Login.CookieName, Value: out.idToken}) //nolint:gosec // a request cookie: only name and value are sent
			return false
		case errors.Is(err, errRefreshRejected):
			l.logger.InfoContext(r.Context(), "refresh token rejected, falling back to login", "source", src.Name, "err", err)
			clearCookie(w, src, src.Login.RefreshCookieName())
		default:
			rejectUnavailable(w, l.logger, r, reasonLoginUnavailable, err, loginRetry)
			return true
		}
	}
	return false
}

// stripRefreshCookies removes the refresh cookies from r's Cookie header.
func stripRefreshCookies(r *http.Request, srcs []config.JWTSource) {
	names := map[string]bool{}
	for _, s := range srcs {
		names[s.Login.RefreshCookieName()] = true
	}
	all := r.Cookies()
	found := false
	for _, c := range all {
		if names[c.Name] {
			found = true
		}
	}
	if !found {
		return
	}
	r.Header.Del("Cookie")
	for _, c := range all {
		if !names[c.Name] {
			r.AddCookie(c)
		}
	}
}

// redeem exchanges refreshToken for a new ID token, sharing the result
// with concurrent and just-after callers presenting the same token (see
// refreshGrace).
func (l *LoginRegistry) redeem(ctx context.Context, src config.JWTSource, refreshToken string) (refreshOutcome, error) {
	sum := sha256.Sum256([]byte(src.Name + "\x00" + refreshToken))
	key := hex.EncodeToString(sum[:])

	l.refreshMu.Lock()
	now := l.now()
	for k, c := range l.refreshCalls {
		if !c.finished.IsZero() && now.Sub(c.finished) > refreshGrace {
			delete(l.refreshCalls, k)
		}
	}
	if c, ok := l.refreshCalls[key]; ok {
		l.refreshMu.Unlock()
		select {
		case <-c.done:
			return c.out, c.err
		case <-ctx.Done():
			return refreshOutcome{}, ctx.Err()
		}
	}
	c := &refreshCall{done: make(chan struct{})}
	l.refreshCalls[key] = c
	l.refreshMu.Unlock()

	// Detached from this request: other requests are waiting on the
	// result, and one client hanging up must not fail them all.
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loginHTTPTimeout)
	defer cancel()
	c.out, c.err = l.doRefresh(callCtx, src, refreshToken)

	l.refreshMu.Lock()
	c.finished = l.now()
	if c.err != nil {
		// Failures are not remembered: a retry may well succeed.
		delete(l.refreshCalls, key)
	}
	l.refreshMu.Unlock()
	close(c.done)
	return c.out, c.err
}

func (l *LoginRegistry) doRefresh(ctx context.Context, src config.JWTSource, refreshToken string) (refreshOutcome, error) {
	e, err := l.endpoints(ctx, src)
	if err != nil {
		return refreshOutcome{}, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, e.client)

	// An already-expired token with no access token forces a refresh.
	tok, err := l.oauthConfig(src, e).TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && (re.Response.StatusCode == http.StatusBadRequest || re.Response.StatusCode == http.StatusUnauthorized) {
			return refreshOutcome{}, fmt.Errorf("%w: %s", errRefreshRejected, re.ErrorCode)
		}
		return refreshOutcome{}, fmt.Errorf("refresh: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return refreshOutcome{}, fmt.Errorf("%w: token response has no id_token", errRefreshRejected)
	}

	kf, err := l.jwt.Keyfunc(ctx, src)
	if err != nil {
		return refreshOutcome{}, err
	}
	// No nonce check: a refresh response carries none (OIDC Core 12.2).
	claims, err := verify(rawID, src, kf)
	if err != nil {
		return refreshOutcome{}, fmt.Errorf("%w: id token: %s", errRefreshRejected, classify(err))
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return refreshOutcome{}, fmt.Errorf("%w: id token has no exp", errRefreshRejected)
	}
	maxAge := int(time.Until(exp.Time).Seconds())
	if maxAge <= 0 || len(rawID) > maxCookieValueLen {
		return refreshOutcome{}, fmt.Errorf("%w: unusable id token", errRefreshRejected)
	}

	next := tok.RefreshToken
	if next == "" {
		next = refreshToken
	}
	return refreshOutcome{idToken: rawID, refreshToken: next, maxAge: maxAge}, nil
}
