package authn

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/promlabel"
)

// resolvePromLabels decides what outbound.prom_label_proxy does with a request
// the ACL allowed, returning it with the verdict in its context. It writes a
// 403 and returns false when there is no way to enforce it: no rule for the
// principal, a label with no value, or a path that isn't enforced.
func resolvePromLabels(w http.ResponseWriter, r *http.Request, cfg *config.Config, p *principal, logger *slog.Logger) (*http.Request, bool) {
	block := cfg.Outbound.PromLabelProxy
	if block == nil {
		return r, true
	}
	allow := func(s promlabel.Scope) (*http.Request, bool) {
		return r.WithContext(promlabel.WithScope(r.Context(), s)), true
	}
	deny := func(detail string) (*http.Request, bool) {
		rejectForbiddenFor(w, logger, r, p, reasonPromLabelDenied, "detail", detail)
		return nil, false
	}

	if p == nil {
		return deny("no_identity")
	}
	if anyPrincipalMatches(block.Exempt, p) {
		return allow(promlabel.Scope{Bypass: true})
	}

	var rule *config.PromLabelRule
	for i := range block.Rules {
		if anyPrincipalMatches(block.Rules[i].Principals, p) {
			rule = &block.Rules[i]
			break
		}
	}
	if rule == nil {
		return deny("no_rule")
	}

	ls := make([]promlabel.Label, 0, len(rule.Labels))
	for _, l := range rule.Labels {
		values := l.Values(claimStrings(p.claims[l.Claim]))
		if len(values) == 0 {
			return deny("no_label_value")
		}
		ls = append(ls, promlabel.Label{Name: l.Name, Values: values})
	}

	// The ACL only checks this with rules present, and passthrough_paths has
	// the same exposure: "/ui/../api/v1/read" starts with "/ui/".
	if uncleanPath(r) {
		return deny("unclean_path")
	}
	if len(block.PassthroughPaths) > 0 && pathMatches(block.PassthroughPaths, r.URL.Path) {
		return allow(promlabel.Scope{Bypass: true})
	}
	endpoint, prefix, ok := promlabel.Route(block.Prefixes(), r.Method, r.URL.Path)
	if !ok {
		return deny("unenforced_path")
	}
	return allow(promlabel.Scope{Labels: ls, Endpoint: endpoint, Prefix: prefix})
}

// claimStrings is every value of a claim in printed form: a list element by
// element, a scalar on its own, matching how claimContains compares them.
func claimStrings(claim any) []string {
	switch c := claim.(type) {
	case nil:
		return nil
	case []string:
		return c
	case []any:
		out := make([]string, 0, len(c))
		for _, v := range c {
			if s, ok := scalarString(v); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		if s, ok := scalarString(c); ok {
			return []string{s}
		}
		return nil
	}
}

func scalarString(v any) (string, bool) {
	switch s := v.(type) {
	case nil, []any, map[string]any:
		return "", false
	case string:
		return s, true
	case float64:
		// JSON numbers decode as float64; %v would print 1000000 as "1e+06".
		return strconv.FormatFloat(s, 'f', -1, 64), true
	default:
		return fmt.Sprint(s), true
	}
}
