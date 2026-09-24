package authn

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/crewjam/saml/samlsp"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// principal is the authenticated identity an ACL rule is matched against.
// source is only set for JWT (the source Name that verified the token).
// claims holds JWT claims or SAML attributes.
type principal struct {
	mode    string
	source  string
	subject string
	claims  map[string]any
}

func basicPrincipal(username string) *principal {
	return &principal{mode: config.ACLModeBasic, subject: username}
}

func jwtPrincipal(src config.JWTSource, claims map[string]any) *principal {
	sub, _ := claims["sub"].(string)
	return &principal{mode: config.ACLModeJWT, source: src.Name, subject: sub, claims: claims}
}

func samlPrincipal(s samlsp.Session) *principal {
	sc, ok := s.(samlSessionClaims)
	if !ok {
		return nil
	}
	claims := make(map[string]any, len(sc.Attributes))
	for k, v := range sc.Attributes {
		claims[k] = v
	}
	return &principal{mode: config.ACLModeSAML, subject: sc.Subject, claims: claims}
}

// authorize reports whether r may proceed under rules, writing a 403
// itself when it may not. With no rules, everything is allowed and r is
// never inspected. A nil p (no authenticated identity) matches no rule.
func authorize(w http.ResponseWriter, r *http.Request, rules []config.ACLRule, p *principal, logger *slog.Logger) bool {
	if len(rules) == 0 {
		return true
	}
	// Rules match the clean, decoded path, so anything the backend might
	// resolve differently ("..", "//", an encoded "/") is refused outright.
	if !config.IsCleanPath(r.URL.Path) || strings.Contains(strings.ToLower(r.URL.RawPath), "%2f") {
		rejectForbidden(w, logger, r, p, "unclean_path", true)
		return false
	}
	if aclAllows(rules, p, r.Method, r.URL.Path) {
		return true
	}
	rejectForbidden(w, logger, r, p)
	return false
}

// aclHandler applies authorize to the SAML leg, whose identity only
// exists in the request context once samlsp.RequireAccount has accepted
// the session.
func aclHandler(rules []config.ACLRule, logger *slog.Logger, next http.Handler) http.Handler {
	if len(rules) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p *principal
		if s := samlsp.SessionFromContext(r.Context()); s != nil {
			p = samlPrincipal(s)
		}
		if authorize(w, r, rules, p, logger) {
			next.ServeHTTP(w, r)
		}
	})
}

func aclAllows(rules []config.ACLRule, p *principal, method, path string) bool {
	if p == nil {
		return false
	}
	for _, rule := range rules {
		if methodMatches(rule.Methods, method) && pathMatches(rule.Paths, path) && anyPrincipalMatches(rule.Principals, p) {
			return true
		}
	}
	return false
}

func methodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == config.ACLWildcard || strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func pathMatches(paths []string, path string) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		if prefix, ok := strings.CutSuffix(p, config.ACLWildcard); ok {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

func anyPrincipalMatches(principals []config.ACLPrincipal, p *principal) bool {
	for _, pr := range principals {
		if principalMatches(pr, p) {
			return true
		}
	}
	return false
}

func principalMatches(pr config.ACLPrincipal, p *principal) bool {
	if pr.Mode != p.mode {
		return false
	}
	if pr.Source != "" && pr.Source != p.source {
		return false
	}
	if pr.Subject != "" && pr.Subject != p.subject {
		return false
	}
	for name, want := range pr.Claims {
		if !claimContains(p.claims[name], want) {
			return false
		}
	}
	return true
}

// claimContains reports whether claim equals want, or is an array with an
// element equal to want. Non-string scalars (bool, number) compare by
// their printed form, so a rule can say "true" or "42".
func claimContains(claim any, want string) bool {
	switch c := claim.(type) {
	case nil:
		return false
	case []any:
		for _, v := range c {
			if scalarEquals(v, want) {
				return true
			}
		}
		return false
	case []string:
		for _, v := range c {
			if v == want {
				return true
			}
		}
		return false
	default:
		return scalarEquals(c, want)
	}
}

func scalarEquals(v any, want string) bool {
	switch s := v.(type) {
	case nil, []any, map[string]any:
		return false
	case string:
		return s == want
	case float64:
		// JSON numbers decode as float64; %v would print 1000000 as "1e+06".
		return strconv.FormatFloat(s, 'f', -1, 64) == want
	default:
		return fmt.Sprint(s) == want
	}
}

// rejectForbidden writes a minimal 403 for an authenticated request no
// ACL rule allows. Only the reason is a metric label; the subject is
// logged, never exported, so /metrics can't enumerate identities.
func rejectForbidden(w http.ResponseWriter, logger *slog.Logger, r *http.Request, p *principal, extra ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("forbidden"))

	fields := []any{"reason", string(reasonACLDenied), "method", r.Method, "path", r.URL.Path}
	if p != nil {
		fields = append(fields, "mode", p.mode, "subject", truncate(p.subject, maxLoggedUsernameLen))
		if p.source != "" {
			fields = append(fields, "source", p.source)
		}
	}
	logger.InfoContext(r.Context(), "rejected request", append(fields, extra...)...)
	recordRejection(r.Context(), reasonACLDenied)
}
