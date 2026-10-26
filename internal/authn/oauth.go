package authn

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/oauth"
)

// isOAuthRoute reports whether path belongs to the OAuth server.
func isOAuthRoute(path string) bool {
	return path == config.OAuthPathPrefix || strings.HasPrefix(path, config.OAuthPathPrefix+"/")
}

// serveOAuth serves the OAuth server's routes, which sit in front of every
// credential check: an MCP client starting a login has none yet, and the
// login route does its own authentication. Like the other /_tap/ routes
// they skip the ACL; what a person may reach is decided at login and by
// the ACL on the requests their token makes.
func serveOAuth(w http.ResponseWriter, r *http.Request, cfg *config.Config, regs authRegistries, reg *oauth.Registry, logger *slog.Logger) {
	if r.URL.Path != config.OAuthPathPrefix+"/login" {
		reg.ServeHTTP(w, r)
		return
	}
	reg.ServeLogin(w, r, func(w http.ResponseWriter, r *http.Request, allow func(oauth.Identity)) {
		authenticate(w, r, cfg, regs, logger, func(p *principal, _ *http.Request) {
			if p == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// A token this server issued is not a login: accepting it here would
			// let anyone holding a stolen access token mint a fresh refresh token
			// and so outlive both the token's expiry and the refresh lifetime.
			if p.mode == config.ACLModeJWT && p.source == config.OAuthSourceName {
				logger.InfoContext(r.Context(), "oauth login rejected", "reason", "login with an issued token", "subject", truncate(p.identity(), maxLoggedUsernameLen))
				http.Error(w, "sign in with your identity provider, not with a token", http.StatusForbidden)
				return
			}
			allow(oauth.Identity{Mode: p.mode, Username: p.username, Claims: p.claims})
		})
	}, tokenPermit(cfg))
}

// tokenPermit answers whether the ACL lets a token with the given claims use
// the MCP endpoint, by building the principal that token will have when it
// comes back through the JWT leg: the proxy's own source, with the claims
// it is issued with. With no ACL rules everyone authenticated is allowed, as
// everywhere else.
func tokenPermit(cfg *config.Config) oauth.Permit {
	return func(sub, email string, groups []string) bool {
		if len(cfg.ACL) == 0 {
			return true
		}
		u, err := url.Parse(cfg.Inbound.OAuthServer.MCPURL)
		if err != nil {
			return false
		}
		claims := map[string]any{"sub": sub, "groups": groups}
		if email != "" {
			claims["email"] = email
		}
		p := &principal{mode: config.ACLModeJWT, source: config.OAuthSourceName, claims: claims}
		return aclAllows(cfg.ACL, p, http.MethodPost, u.Path)
	}
}
