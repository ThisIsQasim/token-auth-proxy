// Package promlabel enforces Prometheus label matchers on forwarded requests,
// with values authn resolved from the caller's claims. Requests are rewritten
// here and sent on through the proxy's normal forwarder, so transport, tracing
// and hot reload behave as for any other request.
package promlabel

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
)

// Label is one enforced label and the values the caller may see for it.
type Label struct {
	Name   string
	Values []string
}

// allows reports whether value is one the caller holds for this label.
func (l Label) allows(value string) bool {
	return slices.Contains(l.Values, value)
}

// matcher is label="v" for one value, or an escaped label=~"a|b" for several,
// so a claim value can never act as a pattern.
func (l Label) matcher() (*labels.Matcher, error) {
	if len(l.Values) == 1 {
		return labels.NewMatcher(labels.MatchEqual, l.Name, l.Values[0])
	}
	quoted := make([]string, len(l.Values))
	for i, v := range l.Values {
		quoted[i] = regexp.QuoteMeta(v)
	}
	return labels.NewMatcher(labels.MatchRegexp, l.Name, strings.Join(quoted, "|"))
}

// Scope is authn's verdict on a request it let through: forward it untouched
// (Bypass), or enforce Labels on Endpoint.
type Scope struct {
	Bypass   bool
	Labels   []Label
	Endpoint Endpoint
	Prefix   string
}

type scopeKey struct{}

// WithScope records the verdict for the handler to act on.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

func scopeFrom(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey{}).(Scope)
	return s, ok
}

// Endpoint is how a request to one API path is enforced.
type Endpoint int

const (
	endpointNone      Endpoint = iota
	endpointQuery              // PromQL in the query parameter
	endpointMatch              // selectors in match[]
	endpointRules              // response filtered by rule labels
	endpointAlerts             // response filtered by alert labels
	endpointAMFilter           // Alertmanager filter parameter
	endpointSilences           // silence list and create
	endpointSilenceID          // silence delete
)

// Route finds the endpoint for method and path under prefixes, which must be
// longest first. Only the longest matching prefix is considered, so a path
// can't fall back to a shorter one. ok is false for anything not enforced.
func Route(prefixes []string, method, path string) (e Endpoint, prefix string, ok bool) {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			e := endpointFor(method, strings.TrimPrefix(path, p))
			return e, p, e != endpointNone
		}
	}
	return endpointNone, "", false
}

func endpointFor(method, path string) Endpoint {
	get := method == "GET"
	getOrPost := get || method == "POST"
	switch path {
	case "/api/v1/query", "/api/v1/query_range", "/api/v1/query_exemplars":
		if getOrPost {
			return endpointQuery
		}
	case "/api/v1/series", "/api/v1/labels":
		if getOrPost {
			return endpointMatch
		}
	case "/federate":
		if get {
			return endpointMatch
		}
	case "/api/v1/rules":
		if get {
			return endpointRules
		}
	case "/api/v1/alerts":
		if get {
			return endpointAlerts
		}
	case "/api/v2/alerts", "/api/v2/alerts/groups":
		if get {
			return endpointAMFilter
		}
	case "/api/v2/silences":
		if getOrPost {
			return endpointSilences
		}
	}
	if get && isLabelValuesPath(path) {
		return endpointMatch
	}
	if method == "DELETE" && strings.HasPrefix(path, silencePathPrefix) {
		return endpointSilenceID
	}
	return endpointNone
}

// isLabelValuesPath matches /api/v1/label/<name>/values.
func isLabelValuesPath(path string) bool {
	name, ok := strings.CutPrefix(path, "/api/v1/label/")
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "/values")
	return ok && name != "" && !strings.Contains(name, "/")
}
