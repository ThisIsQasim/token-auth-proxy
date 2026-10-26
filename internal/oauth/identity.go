package oauth

import (
	"fmt"
	"strings"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// Identity is who the proxy authenticated: the principal of whichever login
// method ran, in a form that does not depend on the authn package.
type Identity struct {
	Mode     string         // "basic", "jwt" or "saml"
	Username string         // the Basic username; empty for the other modes
	Claims   map[string]any // JWT claims or SAML attributes, with the subject under "sub"
}

// maxLoggedSubject bounds a subject written to a log line.
const maxLoggedSubject = 128

// extract reads the subject, email and groups out of the login using the
// configured claim names. Values are copied as they are, apart from taking
// the first of a multi-valued subject or email attribute (SAML attributes
// are lists) and turning groups into a list of strings.
func (id Identity) extract(names config.TokenClaims) (sub, email string, groups []string, err error) {
	if id.Username != "" {
		sub = id.Username
	} else {
		sub = firstString(id.Claims[names.Subject])
	}
	if sub == "" {
		return "", "", nil, fmt.Errorf("login has no %q claim to use as the subject", names.Subject)
	}
	return sub, firstString(id.Claims[names.Email]), stringList(id.Claims[names.Groups]), nil
}

// firstString returns v if it is a string, or the first string of a list.
func firstString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				return s
			}
		}
	}
	return ""
}

// stringList turns a groups claim (a string, a []string from a SAML
// attribute, or a []any from JSON) into a list, dropping anything that is
// not a non-empty string.
func stringList(v any) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	switch t := v.(type) {
	case string:
		add(t)
	case []string:
		for _, s := range t {
			add(s)
		}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	}
	return out
}
