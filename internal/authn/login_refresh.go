package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	http.SetCookie(w, loginCookie(src, src.Login.CookieName, idToken, maxAge))
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
	http.SetCookie(w, loginCookie(src, src.Login.RefreshCookieName(), refreshToken, int(src.Login.RefreshMaxAge.Seconds())))
}

// TakeRefreshCookies removes every refresh cookie from r and returns
// their values by source name. It runs before any leg of the middleware
// decides, so a refresh token never reaches the backend whichever way
// the request is authenticated; Refresh is handed what was taken.
func TakeRefreshCookies(r *http.Request, auth config.InboundAuthConfig) map[string]string {
	var names map[string]string // cookie name -> source name
	for i := range auth.JWT {
		if j := &auth.JWT[i]; j.LoginEnabled() && j.Login.Refresh {
			if names == nil {
				names = map[string]string{}
			}
			names[j.Login.RefreshCookieName()] = j.Name
		}
	}
	if names == nil || r.Header.Get("Cookie") == "" {
		return nil
	}

	var taken map[string]string
	var kept []string
	changed := false
	// Filter the raw header rather than rebuilding it from r.Cookies(),
	// which would re-encode (or drop) the backend's own cookies.
	for _, line := range r.Header.Values("Cookie") {
		var lineKept []string
		for _, part := range strings.Split(line, ";") {
			name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
			if src, ok := names[name]; ok {
				if taken == nil {
					taken = map[string]string{}
				}
				taken[src] = strings.Trim(value, `"`)
				changed = true
				continue
			}
			lineKept = append(lineKept, strings.TrimSpace(part))
		}
		if len(lineKept) > 0 {
			kept = append(kept, strings.Join(lineKept, "; "))
		}
	}
	if changed {
		r.Header.Del("Cookie")
		for _, k := range kept {
			r.Header.Add("Cookie", k)
		}
	}
	return taken
}

// Refresh renews the session of a request that carries a refresh token
// (as returned by TakeRefreshCookies) but no credential at all: the ID
// token cookie has expired and been dropped by the browser. On success
// the new cookies are set on the response and the new ID token is added
// to r, so the request goes on through the ordinary JWT leg as if it had
// never expired.
//
// It reports whether it wrote a response (the IdP was unreachable), in
// which case the caller must stop.
func (l *LoginRegistry) Refresh(w http.ResponseWriter, r *http.Request, cfg *config.Config, tokens map[string]string) (responded bool) {
	if len(tokens) == 0 {
		return false
	}
	if _, ok := extractToken(r, cfg.Inbound.Auth); ok {
		return false
	}

	for i := range cfg.Inbound.Auth.JWT {
		src := cfg.Inbound.Auth.JWT[i]
		rt := tokens[src.Name]
		if rt == "" || !src.LoginEnabled() || !src.Login.Refresh {
			continue
		}
		out, err := l.redeem(r.Context(), src, rt)
		switch {
		case err == nil:
			l.setSession(w, r, src, out.idToken, out.maxAge, out.refreshToken)
			r.AddCookie(&http.Cookie{Name: src.Login.CookieName, Value: out.idToken}) //nolint:gosec // a request cookie: only name and value are sent
			return false
		case errors.Is(err, errRefreshRejected):
			l.logger.InfoContext(r.Context(), "refresh token rejected, falling back to login", "source", src.Name, "err", err)
			http.SetCookie(w, loginCookie(src, src.Login.RefreshCookieName(), "", -1))
		default:
			rejectUnavailable(w, l.logger, r, reasonLoginUnavailable, err, loginRetry)
			return true
		}
	}
	return false
}

// redeem exchanges refreshToken for a new ID token, sharing the result
// with concurrent and just-after callers presenting the same token (see
// refreshGrace).
func (l *LoginRegistry) redeem(ctx context.Context, src config.JWTSource, refreshToken string) (refreshOutcome, error) {
	sum := sha256.Sum256([]byte(src.Name + "\x00" + refreshToken))
	key := hex.EncodeToString(sum[:])

	l.refreshMu.Lock()
	if c, ok := l.refreshCalls[key]; ok && (c.finished.IsZero() || l.now().Sub(c.finished) <= refreshGrace) {
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
	} else {
		// The entry holds live tokens, so it is dropped when the grace
		// ends rather than whenever the next refresh happens to prune it.
		time.AfterFunc(refreshGrace, func() {
			l.refreshMu.Lock()
			defer l.refreshMu.Unlock()
			if l.refreshCalls[key] == c {
				delete(l.refreshCalls, key)
			}
		})
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

	// No nonce check: a refresh response carries none (OIDC Core 12.2).
	_, maxAge, err := l.verifyIDToken(ctx, src, rawID)
	if errors.Is(err, errKeysUnavailable) {
		return refreshOutcome{}, err
	}
	if err != nil {
		return refreshOutcome{}, fmt.Errorf("%w: %w", errRefreshRejected, err)
	}

	next := tok.RefreshToken
	if next == "" {
		next = refreshToken
	}
	return refreshOutcome{idToken: rawID, refreshToken: next, maxAge: maxAge}, nil
}
