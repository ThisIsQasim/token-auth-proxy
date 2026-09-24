package config

import (
	"fmt"
	"path"
	"strings"
)

// ACL modes a principal can name, one per inbound auth mode.
const (
	ACLModeBasic = "basic"
	ACLModeJWT   = "jwt"
	ACLModeSAML  = "saml"
)

// ACLWildcard is the Methods entry matching every method, and the
// trailing path segment ("/x/*") marking a prefix match.
const ACLWildcard = "*"

// ACLRule grants every principal in Principals access to requests whose
// method is in Methods and whose path matches one of Paths. An empty
// Methods or Paths matches everything. With no rules at all, every
// authenticated request is allowed; with any rule, a request no rule
// matches is denied.
type ACLRule struct {
	Principals []ACLPrincipal `yaml:"principals"`
	Methods    []string       `yaml:"methods,omitempty"`
	Paths      []string       `yaml:"paths,omitempty"`
}

// ACLPrincipal matches an authenticated identity. Every field that is set
// must match. Subject is the Basic username, the JWT sub claim or the SAML
// NameID. Source names a JWT source and is only valid for jwt. Claims are
// JWT claims or SAML attributes; a value matches a claim equal to it or an
// array claim containing it.
type ACLPrincipal struct {
	Mode    string            `yaml:"mode"`
	Source  string            `yaml:"source,omitempty"`
	Subject string            `yaml:"subject,omitempty"`
	Claims  map[string]string `yaml:"claims,omitempty"`
}

func applyACLDefaults(rules []ACLRule) {
	for i := range rules {
		for j, m := range rules[i].Methods {
			rules[i].Methods[j] = strings.ToUpper(m)
		}
	}
}

// validateACL checks rules against auth, so a principal naming a JWT
// source or Basic user that doesn't exist fails at load time rather than
// silently never matching.
func validateACL(rules []ACLRule, auth InboundAuthConfig) error {
	for i, rule := range rules {
		if err := validateACLRule(rule, auth); err != nil {
			return fmt.Errorf("acl[%d]: %w", i, err)
		}
	}
	return nil
}

func validateACLRule(rule ACLRule, auth InboundAuthConfig) error {
	if len(rule.Principals) == 0 {
		return fmt.Errorf("principals is required and must list at least one principal")
	}
	for i, p := range rule.Principals {
		if err := validateACLPrincipal(p, auth); err != nil {
			return fmt.Errorf("principals[%d]: %w", i, err)
		}
	}

	for i, m := range rule.Methods {
		if m == ACLWildcard {
			if len(rule.Methods) > 1 {
				return fmt.Errorf("methods: %q already matches every method and can't be combined with others", ACLWildcard)
			}
			continue
		}
		if !isHTTPToken(m) || strings.Contains(m, ACLWildcard) {
			return fmt.Errorf("methods[%d]: %q is not a valid HTTP method", i, m)
		}
	}

	for i, p := range rule.Paths {
		if err := validateACLPath(p); err != nil {
			return fmt.Errorf("paths[%d]: %w", i, err)
		}
	}
	return nil
}

func validateACLPrincipal(p ACLPrincipal, auth InboundAuthConfig) error {
	switch p.Mode {
	case ACLModeBasic, ACLModeJWT, ACLModeSAML:
	default:
		return fmt.Errorf("mode %q must be one of %s, %s, %s", p.Mode, ACLModeBasic, ACLModeJWT, ACLModeSAML)
	}

	if p.Source == "" && p.Subject == "" && len(p.Claims) == 0 {
		return fmt.Errorf("at least one of source, subject or claims is required")
	}

	if p.Source != "" {
		if p.Mode != ACLModeJWT {
			return fmt.Errorf("source is only valid with mode %q", ACLModeJWT)
		}
		if !jwtSourceExists(auth, p.Source) {
			return fmt.Errorf("source %q does not name a configured inbound.auth.jwt source", p.Source)
		}
	}

	if p.Mode == ACLModeBasic {
		if len(p.Claims) > 0 {
			return fmt.Errorf("claims are not available for mode %q", ACLModeBasic)
		}
		if !basicUserExists(auth, p.Subject) {
			return fmt.Errorf("subject %q is not a configured inbound.auth.basic user", p.Subject)
		}
	}

	for name := range p.Claims {
		if name == "" {
			return fmt.Errorf("claims: claim name must not be empty")
		}
	}
	return nil
}

// validateACLPath accepts an exact path or a "/prefix/*" prefix. Paths must
// already be clean, since requests are only matched in clean form.
func validateACLPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%q must begin with %q", p, "/")
	}
	base := p
	if strings.HasSuffix(p, "/"+ACLWildcard) {
		base = strings.TrimSuffix(p, ACLWildcard)
	}
	if strings.Contains(base, ACLWildcard) {
		return fmt.Errorf("%q: %q is only allowed as a trailing %q", p, ACLWildcard, "/"+ACLWildcard)
	}
	if !IsCleanPath(base) {
		return fmt.Errorf("%q must be a clean path (no %q, %q or %q segments)", p, "//", ".", "..")
	}
	return nil
}

// IsCleanPath reports whether p equals path.Clean(p), allowing a single
// trailing slash.
func IsCleanPath(p string) bool {
	trimmed := p
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		trimmed = strings.TrimSuffix(p, "/")
	}
	return path.Clean(trimmed) == trimmed
}

func jwtSourceExists(auth InboundAuthConfig, name string) bool {
	for _, j := range auth.JWT {
		if j.Name == name {
			return true
		}
	}
	return false
}

func basicUserExists(auth InboundAuthConfig, username string) bool {
	if auth.Basic == nil {
		return false
	}
	for _, u := range auth.Basic.Users {
		if u.Username == username {
			return true
		}
	}
	return false
}

// isHTTPToken reports whether s is a non-empty RFC 9110 token.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
