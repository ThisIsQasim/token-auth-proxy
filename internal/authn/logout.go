package authn

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// isLogoutRoute reports whether path is the logout route.
func isLogoutRoute(path string) bool { return path == config.LogoutPath }

// serveLogout ends the browser sessions this proxy holds and sends the
// browser on. It clears the SAML session cookie, every login source's ID
// token and refresh cookies, and the remembered sign-in method, whichever of
// them the request carried: a stale cookie from a source that has since been
// removed is not this route's business, but every configured one is cleared
// so one click signs the browser out of all of them.
//
// Where it sends the browser: the provider's end_session_endpoint when a
// login source with end_session carried an ID token, so the provider's own
// session ends too; otherwise return_to (same-origin only), which for a
// browser with no credential left lands on the sign-in picker.
//
// Basic credentials are not touched: a browser holds those itself and no
// response can clear them. SAML single logout is not supported.
func (l *LoginRegistry) serveLogout(w http.ResponseWriter, r *http.Request, cfg *config.Config, logger *slog.Logger) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth := cfg.Inbound.Auth
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	var endSessionSrc *config.JWTSource
	var idTokenHint string
	for i := range auth.JWT {
		src := &auth.JWT[i]
		if !src.LoginEnabled() {
			continue
		}
		if c, err := r.Cookie(src.Login.CookieName); err == nil && c.Value != "" && src.Login.EndSession && endSessionSrc == nil {
			endSessionSrc, idTokenHint = src, c.Value
		}
		http.SetCookie(w, loginCookie(*src, src.Login.CookieName, "", -1))
		http.SetCookie(w, loginCookie(*src, src.Login.RefreshCookieName(), "", -1))
	}
	if auth.SAMLEnabled() {
		http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the https-ness of sp_base_url, which may legitimately be http in local dev
			Name:     auth.SAML.SessionCookie,
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   strings.HasPrefix(strings.ToLower(auth.SAML.SPBaseURL), "https://"),
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // a UI preference, not a credential; Secure follows the request scheme
		Name:     loginMethodCookie,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")

	target := returnTo
	if endSessionSrc != nil {
		if u, ok := l.endSessionURL(r, *endSessionSrc, idTokenHint); ok {
			target = u
		} else {
			logger.WarnContext(r.Context(), "logout stayed local: no usable end_session_endpoint", "source", endSessionSrc.Name)
		}
	}
	http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // returnTo went through sanitizeReturnTo, and the end-session URL comes from the operator's own discovery document
}

// endSessionURL builds the redirect that ends src's session at the
// provider, or reports false when its discovery document is unavailable or
// advertises no end_session_endpoint.
func (l *LoginRegistry) endSessionURL(r *http.Request, src config.JWTSource, idToken string) (string, bool) {
	e, err := l.endpoints(r.Context(), src)
	if err != nil || e.endSessionURL == "" {
		return "", false
	}
	u, err := url.Parse(e.endSessionURL)
	if err != nil {
		return "", false
	}
	q := u.Query()
	q.Set("id_token_hint", idToken)
	if src.Login.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", src.Login.PostLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}
