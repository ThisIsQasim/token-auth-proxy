package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

var (
	aliceBasic = &principal{mode: config.ACLModeBasic, subject: "alice"}
	botJWT     = &principal{
		mode:    config.ACLModeJWT,
		source:  "ci",
		subject: "bot",
		claims: map[string]any{
			"groups":   []any{"writers", "readers"},
			"team":     "infra",
			"admin":    true,
			"level":    float64(42),
			"org":      float64(1000000),
			"big":      float64(123456789012),
			"ratio":    1.5,
			"ids":      []any{float64(12345678)},
			"nested":   map[string]any{"a": "b"},
			"mixedArr": []any{"x", float64(7), []any{"deep"}},
		},
	}
	carolSAML = &principal{
		mode:    config.ACLModeSAML,
		subject: "carol@example.com",
		claims:  map[string]any{"groups": []string{"admins"}},
	}
)

func rule(p config.ACLPrincipal, methods, paths []string) config.ACLRule {
	return config.ACLRule{Principals: []config.ACLPrincipal{p}, Methods: methods, Paths: paths}
}

var aliceRule = config.ACLPrincipal{Mode: config.ACLModeBasic, Subject: "alice"}

func TestACL_OmittedMethodsAndPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   config.ACLRule
		method string
		path   string
		want   bool
	}{
		{"omitted methods match every method", rule(aliceRule, nil, []string{"/x"}), http.MethodDelete, "/x", true},
		{"omitted methods still enforce paths", rule(aliceRule, nil, []string{"/x"}), http.MethodDelete, "/y", false},
		{"omitted paths match every path", rule(aliceRule, []string{"GET"}, nil), http.MethodGet, "/any/thing", true},
		{"omitted paths still enforce methods", rule(aliceRule, []string{"GET"}, nil), http.MethodPost, "/any/thing", false},
		{"omitting both grants full access", rule(aliceRule, nil, nil), http.MethodPatch, "/whatever", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, aclAllows([]config.ACLRule{tc.rule}, aliceBasic, tc.method, tc.path))
		})
	}
}

func TestACL_Methods(t *testing.T) {
	wildcard := []config.ACLRule{rule(aliceRule, []string{"*"}, nil)}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "PROPFIND"} {
		assert.True(t, aclAllows(wildcard, aliceBasic, m, "/"), "* must match %s", m)
	}

	named := []config.ACLRule{rule(aliceRule, []string{"get", "POST"}, nil)}
	assert.True(t, aclAllows(named, aliceBasic, "GET", "/"), "named methods match case-insensitively")
	assert.True(t, aclAllows(named, aliceBasic, "post", "/"))
	assert.False(t, aclAllows(named, aliceBasic, "DELETE", "/"), "a method not in the list is denied")
}

func TestACL_Paths(t *testing.T) {
	exact := []config.ACLRule{rule(aliceRule, nil, []string{"/api/v1/push"})}
	assert.True(t, aclAllows(exact, aliceBasic, "POST", "/api/v1/push"))
	assert.False(t, aclAllows(exact, aliceBasic, "POST", "/api/v1/push/"), "an exact path matches only itself")
	assert.False(t, aclAllows(exact, aliceBasic, "POST", "/api/v1/pushx"))
	assert.False(t, aclAllows(exact, aliceBasic, "POST", "/api/v1"))

	prefix := []config.ACLRule{rule(aliceRule, nil, []string{"/x/*"})}
	assert.True(t, aclAllows(prefix, aliceBasic, "GET", "/x/"))
	assert.True(t, aclAllows(prefix, aliceBasic, "GET", "/x/a"))
	assert.True(t, aclAllows(prefix, aliceBasic, "GET", "/x/a/b"))
	assert.False(t, aclAllows(prefix, aliceBasic, "GET", "/x"), "/x/* does not match /x itself")
	assert.False(t, aclAllows(prefix, aliceBasic, "GET", "/xy"), "/x/* does not match a sibling sharing the prefix")

	root := []config.ACLRule{rule(aliceRule, nil, []string{"/*"})}
	assert.True(t, aclAllows(root, aliceBasic, "GET", "/"))
	assert.True(t, aclAllows(root, aliceBasic, "GET", "/anything/at/all"))
}

func TestACL_Principals(t *testing.T) {
	for _, tc := range []struct {
		name string
		pr   config.ACLPrincipal
		p    *principal
		want bool
	}{
		{"subject only", config.ACLPrincipal{Mode: "jwt", Subject: "bot"}, botJWT, true},
		{"subject mismatch", config.ACLPrincipal{Mode: "jwt", Subject: "other"}, botJWT, false},
		{"source only", config.ACLPrincipal{Mode: "jwt", Source: "ci"}, botJWT, true},
		{"source mismatch", config.ACLPrincipal{Mode: "jwt", Source: "other"}, botJWT, false},
		{"claims only", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"team": "infra"}}, botJWT, true},
		{"all three combined", config.ACLPrincipal{Mode: "jwt", Source: "ci", Subject: "bot", Claims: map[string]string{"team": "infra", "groups": "writers"}}, botJWT, true},
		{"all three, source mismatched", config.ACLPrincipal{Mode: "jwt", Source: "x", Subject: "bot", Claims: map[string]string{"team": "infra"}}, botJWT, false},
		{"all three, subject mismatched", config.ACLPrincipal{Mode: "jwt", Source: "ci", Subject: "x", Claims: map[string]string{"team": "infra"}}, botJWT, false},
		{"all three, one claim mismatched", config.ACLPrincipal{Mode: "jwt", Source: "ci", Subject: "bot", Claims: map[string]string{"team": "infra", "groups": "admins"}}, botJWT, false},
		{"claim as string", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"team": "infra"}}, botJWT, true},
		{"claim as array containing value", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"groups": "readers"}}, botJWT, true},
		{"claim as array missing value", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"groups": "admins"}}, botJWT, false},
		{"missing claim denies", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"absent": "x"}}, botJWT, false},
		{"bool claim by printed form", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"admin": "true"}}, botJWT, true},
		{"number claim by printed form", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"level": "42"}}, botJWT, true},
		{"large number in plain decimal", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"org": "1000000"}}, botJWT, true},
		{"large number never in scientific notation", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"org": "1e+06"}}, botJWT, false},
		{"twelve-digit number", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"big": "123456789012"}}, botJWT, true},
		{"decimal number", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"ratio": "1.5"}}, botJWT, true},
		{"large number inside an array", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"ids": "12345678"}}, botJWT, true},
		{"object claim never matches", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"nested": "map[a:b]"}}, botJWT, false},
		{"mixed array matches a number element", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"mixedArr": "7"}}, botJWT, true},
		{"mixed array ignores nested arrays", config.ACLPrincipal{Mode: "jwt", Claims: map[string]string{"mixedArr": "deep"}}, botJWT, false},
		{"saml attribute array", config.ACLPrincipal{Mode: "saml", Claims: map[string]string{"groups": "admins"}}, carolSAML, true},
		{"saml nameid", config.ACLPrincipal{Mode: "saml", Subject: "carol@example.com"}, carolSAML, true},
		{"basic username", config.ACLPrincipal{Mode: "basic", Subject: "alice"}, aliceBasic, true},
		{"mode mismatch denies even when subject matches", config.ACLPrincipal{Mode: "jwt", Subject: "alice"}, aliceBasic, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, aclAllows([]config.ACLRule{rule(tc.pr, nil, nil)}, tc.p, "GET", "/"))
		})
	}
}

func TestACL_AnyOf(t *testing.T) {
	secondPrincipal := []config.ACLRule{{
		Principals: []config.ACLPrincipal{
			{Mode: "jwt", Subject: "nobody"},
			{Mode: "basic", Subject: "alice"},
		},
	}}
	assert.True(t, aclAllows(secondPrincipal, aliceBasic, "GET", "/"), "a later principal in a rule matches")

	laterRule := []config.ACLRule{
		rule(config.ACLPrincipal{Mode: "basic", Subject: "bob"}, nil, nil),
		rule(aliceRule, []string{"POST"}, nil),
		rule(aliceRule, nil, []string{"/other"}),
		rule(aliceRule, []string{"GET"}, []string{"/ok"}),
	}
	assert.True(t, aclAllows(laterRule, aliceBasic, "GET", "/ok"), "a later rule matches after earlier ones miss")
	assert.False(t, aclAllows(laterRule, aliceBasic, "GET", "/nope"), "no rule matching denies")

	assert.False(t, aclAllows(laterRule, nil, "GET", "/ok"), "no principal matches nothing")
}

func TestAuthorize_PathHygiene(t *testing.T) {
	rules := []config.ACLRule{rule(aliceRule, nil, []string{"/api/*"})}

	for _, target := range []string{
		"/api/../admin",
		"/api/./x",
		"/api//x",
		"/api/a%2Fb",
		"/api/a%2fb",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			assert.False(t, authorize(rec, r, rules, aliceBasic, testLogger()))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, "forbidden", rec.Body.String())

			rec = httptest.NewRecorder()
			assert.True(t, authorize(rec, r, nil, aliceBasic, testLogger()), "with no rules nothing is inspected")
			assert.Equal(t, http.StatusOK, rec.Code, "with no rules nothing is written")
		})
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/x/", nil)
	assert.True(t, authorize(httptest.NewRecorder(), r, rules, aliceBasic, testLogger()), "a trailing slash is clean")
}
