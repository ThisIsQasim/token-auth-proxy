package authn

import (
	"net/http"
	"strings"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// extractFrom returns the credential at loc in r, with loc.Prefix
// stripped, or ("", false) if that location is absent, doesn't carry
// the required prefix, or is empty once the prefix is removed.
//
// The prefix match is case-insensitive: RFC 7235 auth-scheme tokens are
// case-insensitive, and real clients send "bearer" as often as
// "Bearer". A location that exists but fails the prefix check is
// treated the same as an absent one — the caller moves on to the next
// configured location rather than stopping here.
func extractFrom(r *http.Request, loc config.CredentialLocation) (string, bool) {
	var v string
	switch loc.Location {
	case "header":
		v = r.Header.Get(loc.Name)
	case "cookie":
		c, err := r.Cookie(loc.Name)
		if err != nil {
			return "", false
		}
		v = c.Value
	case "query":
		v = r.URL.Query().Get(loc.Name)
	default:
		// Unreachable in practice: config.Validate already restricts
		// Location to header/cookie/query before this ever runs.
		return "", false
	}

	if v == "" {
		return "", false
	}

	if loc.Prefix != "" {
		if len(v) < len(loc.Prefix) || !strings.EqualFold(v[:len(loc.Prefix)], loc.Prefix) {
			return "", false
		}
		v = v[len(loc.Prefix):]
	}

	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// extractToken walks every enabled JWT source's Credentials, in
// configuration order, source by source, and returns the first
// successfully extracted credential — "first non-empty wins" means
// first successful extraction, not first location that merely exists
// (see extractFrom). Which source's Credentials list produced the
// value is irrelevant beyond this point: routing happens by the
// token's (unverified) iss claim, not by where it was found. Disabled
// sources are skipped — their Credentials are never consulted.
func extractToken(r *http.Request, auth config.InboundAuthConfig) (string, bool) {
	for _, src := range auth.JWT {
		if src.Disabled {
			continue
		}
		for _, loc := range src.Credentials {
			if v, ok := extractFrom(r, loc); ok {
				return v, true
			}
		}
	}
	return "", false
}
