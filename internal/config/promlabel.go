package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/prometheus/common/model"
)

// PromLabelProxyConfig is outbound.prom_label_proxy: Prometheus label
// matchers enforced on the backend leg, with their values taken from the
// caller's claims. Exempt principals are forwarded untouched. Every other
// principal needs a matching rule that yields a value for each of its
// labels, and may only reach the enforced endpoints under PathPrefixes and
// the paths in PassthroughPaths.
type PromLabelProxyConfig struct {
	// PathPrefixes is where the Prometheus and Alertmanager APIs live on the
	// target. Defaults to "/".
	PathPrefixes []string `yaml:"path_prefixes,omitempty"`

	// Exempt principals are forwarded unchanged, on any path.
	Exempt []ACLPrincipal `yaml:"exempt,omitempty"`

	// Rules are tried in order and the first whose principals match wins,
	// unlike ACL rules: the union of two label sets has no single meaning.
	Rules []PromLabelRule `yaml:"rules"`

	// PassthroughPaths are forwarded unchanged for rule-matched principals.
	PassthroughPaths []string `yaml:"passthrough_paths,omitempty"`

	prefixes []string
}

// PromLabelRule enforces Labels on every request from one of Principals.
type PromLabelRule struct {
	Principals []ACLPrincipal `yaml:"principals"`
	Labels     []PromLabel    `yaml:"labels"`
}

// PromLabel maps a claim onto one enforced label. A list claim gives several
// values. Pattern must match a value in full or the value is dropped, and its
// capture group, if it has one, is what the label is set to.
type PromLabel struct {
	Name    string `yaml:"name"`
	Claim   string `yaml:"claim"`
	Pattern string `yaml:"pattern,omitempty"`

	pattern *regexp.Regexp
}

// Prefixes returns the normalized path prefixes, longest first. Empty until
// Validate has succeeded.
func (p *PromLabelProxyConfig) Prefixes() []string { return p.prefixes }

// Values applies the label's pattern to a claim's values, returning the label
// values sorted and without duplicates. An empty value is always dropped: a
// matcher on "" selects series that don't have the label at all.
func (l PromLabel) Values(claim []string) []string {
	var out []string
	for _, v := range claim {
		if l.pattern != nil {
			m := l.pattern.FindStringSubmatch(v)
			if m == nil {
				continue
			}
			v = m[len(m)-1]
		}
		if v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (p *PromLabelProxyConfig) validate(auth InboundAuthConfig) error {
	if !auth.Enabled() {
		return fmt.Errorf("requires an inbound auth method, there is no identity to take label values from")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("rules is required and must list at least one rule")
	}

	for i, pr := range p.Exempt {
		if err := validateACLPrincipal(pr, auth); err != nil {
			return fmt.Errorf("exempt[%d]: %w", i, err)
		}
	}
	for i := range p.Rules {
		if err := p.Rules[i].validate(auth); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	for i, path := range p.PassthroughPaths {
		if err := validateACLPath(path); err != nil {
			return fmt.Errorf("passthrough_paths[%d]: %w", i, err)
		}
	}

	prefixes, err := normalizePromLabelPrefixes(p.PathPrefixes)
	if err != nil {
		return err
	}
	p.prefixes = prefixes
	return nil
}

func normalizePromLabelPrefixes(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{""}, nil
	}
	out := make([]string, 0, len(raw))
	for i, prefix := range raw {
		if strings.Contains(prefix, ACLWildcard) {
			return nil, fmt.Errorf("path_prefixes[%d]: %q must not contain %q", i, prefix, ACLWildcard)
		}
		if err := validateACLPath(prefix); err != nil {
			return nil, fmt.Errorf("path_prefixes[%d]: %w", i, err)
		}
		out = append(out, strings.TrimSuffix(prefix, "/"))
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return slices.Compact(out), nil
}

func (r *PromLabelRule) validate(auth InboundAuthConfig) error {
	if len(r.Principals) == 0 {
		return fmt.Errorf("principals is required and must list at least one principal")
	}
	for i, pr := range r.Principals {
		if err := validatePromLabelPrincipal(pr, auth); err != nil {
			return fmt.Errorf("principals[%d]: %w", i, err)
		}
	}

	// An empty list must not read as "unrestricted": that is what exempt is
	// for, and a mistyped key would otherwise land here silently.
	if len(r.Labels) == 0 {
		return fmt.Errorf("labels is required and must list at least one label")
	}
	seen := make(map[string]bool, len(r.Labels))
	for i := range r.Labels {
		l := &r.Labels[i]
		if err := l.validate(); err != nil {
			return fmt.Errorf("labels[%d]: %w", i, err)
		}
		if seen[l.Name] {
			return fmt.Errorf("labels[%d]: label %q is listed twice", i, l.Name)
		}
		seen[l.Name] = true
	}
	return nil
}

// validatePromLabelPrincipal is validateACLPrincipal, except that a bare mode
// is fine: a rule only ever narrows what a principal sees, so "every SAML
// user" is a safe thing to say here. Basic is refused because it has no claims
// to take a value from.
func validatePromLabelPrincipal(p ACLPrincipal, auth InboundAuthConfig) error {
	if p.Mode == ACLModeBasic {
		return fmt.Errorf("mode %q has no claims to map, list the user under exempt instead", ACLModeBasic)
	}
	if (p.Mode == ACLModeJWT || p.Mode == ACLModeSAML) && p.Source == "" && p.Username == "" && len(p.Claims) == 0 {
		return nil
	}
	return validateACLPrincipal(p, auth)
}

func (l *PromLabel) validate() error {
	if !model.LegacyValidation.IsValidLabelName(l.Name) {
		return fmt.Errorf("name %q is not a valid label name", l.Name)
	}
	if l.Claim == "" {
		return fmt.Errorf("claim is required")
	}

	l.pattern = nil
	if l.Pattern == "" {
		return nil
	}
	// Compiled alone first: wrapped straight away, a pattern like "a)|(b" would
	// balance the wrapper's parentheses and quietly lose its anchors.
	re, err := regexp.Compile(l.Pattern)
	if err != nil {
		return fmt.Errorf("pattern: %w", err)
	}
	if re.NumSubexp() > 1 {
		return fmt.Errorf("pattern %q has %d capture groups, at most one is allowed", l.Pattern, re.NumSubexp())
	}
	l.pattern = regexp.MustCompile("^(?:" + l.Pattern + ")$")
	return nil
}
