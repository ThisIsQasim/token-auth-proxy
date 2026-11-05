package authn

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
	"github.com/ThisIsQasim/token-auth-proxy/internal/promlabel"
)

// promLabelEnv is the middleware with promlabel.Handler after it, as in main.
type promLabelEnv struct {
	*aclEnv
	got *http.Request
}

func newPromLabelEnv(t *testing.T, modes aclModes, block *config.PromLabelProxyConfig) *promLabelEnv {
	t.Helper()
	env := newACLEnv(t, modes, nil, nil)
	e := &promLabelEnv{aclEnv: env}

	next := *env.source.Current()
	next.Outbound.PromLabelProxy = block
	env.source.set(&next)

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.got = r })
	forward := promlabel.New(env.source, backend, nil, slog.New(slog.DiscardHandler))
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	samlReg := NewSAMLRegistry(testLogger())
	t.Cleanup(samlReg.Close)
	env.handler = NewMiddleware(env.source, reg, samlReg, NewBasicRegistry(testLogger()), NewLoginRegistry(reg, testLogger()), nil, testLogger())(forward)
	return e
}

func (e *promLabelEnv) enforcedQuery(t *testing.T) string {
	t.Helper()
	require.NotNil(t, e.got, "nothing reached the backend")
	return e.got.URL.Query().Get("query")
}

func (e *promLabelEnv) claimsToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = e.jwtIDP.Issuer
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	return e.jwtIDP.Sign(t, claims)
}

func groupsRule() config.PromLabelRule {
	return config.PromLabelRule{
		Principals: []config.ACLPrincipal{{Mode: config.ACLModeJWT}},
		Labels:     []config.PromLabel{{Name: "namespace", Claim: "groups", Pattern: "tenant-(.+)"}},
	}
}

const promQuery = "/api/v1/query?query=up"

func TestPromLabels_ClaimValues(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{groupsRule()}}
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   string
	}{
		{"one group", jwt.MapClaims{"groups": []string{"tenant-a", "staff"}}, `up{namespace="a"}`},
		{"several groups", jwt.MapClaims{"groups": []string{"tenant-b", "tenant-a"}}, `up{namespace=~"a|b"}`},
		{"string claim", jwt.MapClaims{"groups": "tenant-a"}, `up{namespace="a"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newPromLabelEnv(t, aclModes{jwt: true}, block)
			rec := e.serve(e.jwtReq(t, http.MethodGet, promQuery, e.claimsToken(t, tt.claims)))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tt.want, e.enforcedQuery(t))
		})
	}
}

func TestPromLabels_NumericClaim(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{{
		Principals: []config.ACLPrincipal{{Mode: config.ACLModeJWT}},
		Labels:     []config.PromLabel{{Name: "org", Claim: "org_id"}},
	}}}
	e := newPromLabelEnv(t, aclModes{jwt: true}, block)
	rec := e.serve(e.jwtReq(t, http.MethodGet, promQuery, e.claimsToken(t, jwt.MapClaims{"org_id": 1000000})))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `up{org="1000000"}`, e.enforcedQuery(t))
}

func TestPromLabels_Denied(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{groupsRule()}, PassthroughPaths: []string{"/ui/*"}}
	tests := []struct {
		name, target string
		claims       jwt.MapClaims
	}{
		{"no claim", promQuery, jwt.MapClaims{}},
		{"no value matches", promQuery, jwt.MapClaims{"groups": []string{"staff"}}},
		{"empty capture", promQuery, jwt.MapClaims{"groups": []string{"tenant-"}}},
		{"object claim", promQuery, jwt.MapClaims{"groups": map[string]any{"a": "tenant-a"}}},
		{"unenforced path", "/api/v1/read", jwt.MapClaims{"groups": []string{"tenant-a"}}},
		{"passthrough escape", "/ui/../api/v1/read", jwt.MapClaims{"groups": []string{"tenant-a"}}},
		{"encoded slash", "/ui%2F..%2Fapi/v1/read", jwt.MapClaims{"groups": []string{"tenant-a"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newPromLabelEnv(t, aclModes{jwt: true}, block)
			r := e.jwtReq(t, http.MethodGet, "/", e.claimsToken(t, tt.claims))
			u, err := url.ParseRequestURI(tt.target)
			require.NoError(t, err)
			r.URL = u
			rec := e.serve(r)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Nil(t, e.got, "must not reach the backend")
		})
	}
}

func TestPromLabels_NoRuleForPrincipal(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{groupsRule()}}
	e := newPromLabelEnv(t, aclModes{basic: true, jwt: true}, block)
	rec := e.serve(e.basicReq(t, http.MethodGet, promQuery, "alice"))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, e.got)
}

func TestPromLabels_Exempt(t *testing.T) {
	block := &config.PromLabelProxyConfig{
		Exempt: []config.ACLPrincipal{{Mode: config.ACLModeBasic, Username: "alice"}},
		Rules:  []config.PromLabelRule{groupsRule()},
	}
	e := newPromLabelEnv(t, aclModes{basic: true, jwt: true}, block)
	rec := e.serve(e.basicReq(t, http.MethodPost, "/api/v1/push?query=up", "alice"))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "up", e.enforcedQuery(t), "forwarded unchanged, on a path rule-matched callers can't use")
}

func TestPromLabels_FirstRuleWins(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{
		{
			Principals: []config.ACLPrincipal{{Mode: config.ACLModeJWT, Claims: map[string]string{"sub": "bot"}}},
			Labels:     []config.PromLabel{{Name: "namespace", Claim: "sub"}},
		},
		groupsRule(),
	}}
	e := newPromLabelEnv(t, aclModes{jwt: true}, block)
	claims := jwt.MapClaims{"sub": "bot", "groups": []string{"tenant-a"}}
	rec := e.serve(e.jwtReq(t, http.MethodGet, promQuery, e.claimsToken(t, claims)))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `up{namespace="bot"}`, e.enforcedQuery(t))
}

func TestPromLabels_Passthrough(t *testing.T) {
	block := &config.PromLabelProxyConfig{Rules: []config.PromLabelRule{groupsRule()}, PassthroughPaths: []string{"/api/v1/status/buildinfo"}}
	e := newPromLabelEnv(t, aclModes{jwt: true}, block)

	token := e.claimsToken(t, jwt.MapClaims{"groups": []string{"tenant-a"}})
	rec := e.serve(e.jwtReq(t, http.MethodGet, "/api/v1/status/buildinfo", token))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, e.got)

	// A caller the rules can't place gets nothing, passthrough or not.
	e.got = nil
	token = e.claimsToken(t, jwt.MapClaims{"groups": []string{"staff"}})
	rec = e.serve(e.jwtReq(t, http.MethodGet, "/api/v1/status/buildinfo", token))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, e.got)
}

func TestPromLabels_SAMLAttributes(t *testing.T) {
	p := &principal{mode: config.ACLModeSAML, claims: map[string]any{"groups": []string{"tenant-a", "staff"}}}
	cfg := &config.Config{Outbound: config.OutboundConfig{PromLabelProxy: &config.PromLabelProxyConfig{}}}
	cfg.Outbound.PromLabelProxy.Rules = []config.PromLabelRule{{
		Principals: []config.ACLPrincipal{{Mode: config.ACLModeSAML}},
		Labels:     []config.PromLabel{{Name: "namespace", Claim: "groups"}},
	}}
	cfg.Inbound.Auth.Basic = &config.BasicSource{Realm: "r", Users: []config.BasicUser{{Username: "u", PasswordHash: "$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"}}}
	cfg.ListenAddr, cfg.Target = ":0", "http://localhost:1"
	require.NoError(t, cfg.Validate())

	rec := httptest.NewRecorder()
	r, ok := resolvePromLabels(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, promQuery, nil), cfg, p, testLogger())
	require.True(t, ok, rec.Body.String())
	assert.NotNil(t, r)
}

func TestPromLabels_NoIdentity(t *testing.T) {
	cfg := &config.Config{Outbound: config.OutboundConfig{PromLabelProxy: &config.PromLabelProxyConfig{}}}
	rec := httptest.NewRecorder()
	_, ok := resolvePromLabels(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, promQuery, nil), cfg, nil, testLogger())
	assert.False(t, ok)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestClaimStrings(t *testing.T) {
	assert.Nil(t, claimStrings(nil))
	assert.Equal(t, []string{"a"}, claimStrings("a"))
	assert.Equal(t, []string{"a", "b"}, claimStrings([]string{"a", "b"}))
	assert.Equal(t, []string{"a", "1000000", "true"}, claimStrings([]any{"a", float64(1000000), true, nil, []any{"x"}}))
	assert.Equal(t, []string{"true"}, claimStrings(true))
	assert.Nil(t, claimStrings(map[string]any{"a": "b"}))
}
