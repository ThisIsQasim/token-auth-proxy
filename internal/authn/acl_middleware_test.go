package authn

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// aclEnv is one middleware under test with the fixtures it trusts.
type aclEnv struct {
	handler http.Handler
	backend *backendStub
	source  *fakeSource
	jwtIDP  *TestIDP
	samlIDP *TestSAMLIDP
	samlSrc config.SAMLSource
}

type aclModes struct {
	basic, jwt, saml bool
}

func newACLEnv(t *testing.T, modes aclModes, rules []config.ACLRule, logger *slog.Logger) *aclEnv {
	t.Helper()
	if logger == nil {
		logger = testLogger()
	}
	env := &aclEnv{backend: &backendStub{}}
	auth := config.InboundAuthConfig{}

	if modes.basic {
		src := basicSourceFor(t)
		src.Users = append(src.Users, config.BasicUser{Username: "bob", PasswordHash: src.Users[0].PasswordHash})
		auth.Basic = &src
	}
	if modes.jwt {
		env.jwtIDP = NewTestIDP(t)
		auth.JWT = []config.JWTSource{jwtSourceFor(env.jwtIDP)}
	}
	if modes.saml {
		t.Setenv("ACL_TEST_SAML_KEY", validSAMLSessionKeyForTest)
		env.samlIDP = NewTestSAMLIDP(t)
		env.samlIDP.SetUser("carol@example.com", map[string][]string{"groups": {"admins", "staff"}})
		env.samlSrc = samlSourceFor(t, env.samlIDP, "ACL_TEST_SAML_KEY")
		auth.SAML = &env.samlSrc
	}

	env.source = newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: auth}, ACL: rules})

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	samlReg := NewSAMLRegistry(testLogger())
	t.Cleanup(samlReg.Close)
	env.handler = NewMiddleware(env.source, reg, samlReg, NewBasicRegistry(testLogger()), logger)(env.backend.Handler())
	return env
}

// setRules hot-swaps the live ACL, keeping auth unchanged.
func (e *aclEnv) setRules(t *testing.T, rules []config.ACLRule) {
	t.Helper()
	next := *e.source.Current()
	next.ACL = rules
	e.source.set(&next)
}

func (e *aclEnv) serve(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, r)
	return rec
}

func (e *aclEnv) basicReq(t *testing.T, method, target, user string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	r.SetBasicAuth(user, "hunter2")
	return r
}

func (e *aclEnv) token(t *testing.T, sub string, groups ...string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": e.jwtIDP.Issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": sub,
	}
	if groups != nil {
		claims["groups"] = groups
	}
	return e.jwtIDP.Sign(t, claims)
}

func (e *aclEnv) jwtReq(t *testing.T, method, target, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// samlLogin drives a full SP-initiated login and returns the session
// cookie, failing the test if the ACS leg doesn't hand one out.
func (e *aclEnv) samlLogin(t *testing.T) *http.Cookie {
	t.Helper()
	start := e.serve(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil))
	require.Equal(t, http.StatusFound, start.Code)
	tracker := findCookie(start.Result(), "saml_")
	require.NotNil(t, tracker)

	loc := start.Result().Header.Get("Location")
	u, err := url.Parse(loc)
	require.NoError(t, err)
	form := url.Values{"SAMLResponse": {driveIDPLogin(t, loc)}, "RelayState": {u.Query().Get("RelayState")}}
	acsReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, e.samlSrc.ACSPath, strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsReq.AddCookie(tracker)
	acs := e.serve(acsReq)
	require.Equal(t, http.StatusFound, acs.Code, "the ACS path must work regardless of ACL rules")
	session := findCookie(acs.Result(), e.samlSrc.SessionCookie)
	require.NotNil(t, session)
	return session
}

func (e *aclEnv) samlReq(t *testing.T, method, target string, session *http.Cookie) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	r.AddCookie(session)
	return r
}

func assertForbidden(t *testing.T, rec *httptest.ResponseRecorder, backend *backendStub, wantHits int) {
	t.Helper()
	assertRejected(t, rec, backend, wantHits, http.StatusForbidden, "forbidden")
}

func TestMiddlewareACL_NoRules_AllowsEverything(t *testing.T) {
	const unclean = "/a/../b//c"

	t.Run("basic", func(t *testing.T) {
		env := newACLEnv(t, aclModes{basic: true}, nil, nil)
		assertProxied(t, env.serve(env.basicReq(t, http.MethodDelete, "/anything", "bob")), env.backend, 1)
		assertProxied(t, env.serve(env.basicReq(t, http.MethodGet, unclean, "alice")), env.backend, 2)
	})
	t.Run("jwt", func(t *testing.T) {
		env := newACLEnv(t, aclModes{jwt: true}, nil, nil)
		assertProxied(t, env.serve(env.jwtReq(t, http.MethodPut, "/anything", env.token(t, "bot"))), env.backend, 1)
		assertProxied(t, env.serve(env.jwtReq(t, http.MethodGet, unclean, env.token(t, "bot"))), env.backend, 2)
	})
	t.Run("saml", func(t *testing.T) {
		env := newACLEnv(t, aclModes{saml: true}, nil, nil)
		session := env.samlLogin(t)
		assertProxied(t, env.serve(env.samlReq(t, http.MethodPost, "/anything", session)), env.backend, 1)
		assertProxied(t, env.serve(env.samlReq(t, http.MethodGet, unclean, session)), env.backend, 2)
	})
	t.Run("no auth", func(t *testing.T) {
		env := newACLEnv(t, aclModes{}, nil, nil)
		assertProxied(t, env.serve(httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/anything", nil)), env.backend, 1)
		assertProxied(t, env.serve(httptest.NewRequestWithContext(t.Context(), http.MethodGet, unclean, nil)), env.backend, 2)
	})
}

func TestMiddlewareACL_Basic(t *testing.T) {
	env := newACLEnv(t, aclModes{basic: true}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "basic", Subject: "alice"}},
		Methods:    []string{"POST"},
		Paths:      []string{"/api/v1/push"},
	}}, nil)

	assertProxied(t, env.serve(env.basicReq(t, http.MethodPost, "/api/v1/push", "alice")), env.backend, 1)
	assertForbidden(t, env.serve(env.basicReq(t, http.MethodGet, "/api/v1/push", "alice")), env.backend, 1)
	assertForbidden(t, env.serve(env.basicReq(t, http.MethodPost, "/api/v1/query", "alice")), env.backend, 1)
	assertForbidden(t, env.serve(env.basicReq(t, http.MethodPost, "/api/v1/push", "bob")), env.backend, 1)
}

func TestMiddlewareACL_JWT(t *testing.T) {
	env := newACLEnv(t, aclModes{jwt: true}, nil, nil)
	env.setRules(t, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{
			Mode:    "jwt",
			Source:  env.jwtIDP.Issuer,
			Subject: "bot",
			Claims:  map[string]string{"groups": "writers"},
		}},
		Paths: []string{"/api/*"},
	}})

	assertProxied(t, env.serve(env.jwtReq(t, http.MethodGet, "/api/x", env.token(t, "bot", "readers", "writers"))), env.backend, 1)
	assertForbidden(t, env.serve(env.jwtReq(t, http.MethodGet, "/api/x", env.token(t, "bot", "readers"))), env.backend, 1)
	assertForbidden(t, env.serve(env.jwtReq(t, http.MethodGet, "/api/x", env.token(t, "bot"))), env.backend, 1)
	assertForbidden(t, env.serve(env.jwtReq(t, http.MethodGet, "/api/x", env.token(t, "other", "writers"))), env.backend, 1)
	assertForbidden(t, env.serve(env.jwtReq(t, http.MethodGet, "/other", env.token(t, "bot", "writers"))), env.backend, 1)
}

func TestMiddlewareACL_SAML(t *testing.T) {
	env := newACLEnv(t, aclModes{saml: true}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "saml", Subject: "carol@example.com", Claims: map[string]string{"groups": "admins"}}},
		Methods:    []string{"GET"},
		Paths:      []string{"/protected"},
	}}, nil)
	session := env.samlLogin(t)

	assertProxied(t, env.serve(env.samlReq(t, http.MethodGet, "/protected", session)), env.backend, 1)
	assertForbidden(t, env.serve(env.samlReq(t, http.MethodPost, "/protected", session)), env.backend, 1)
	assertForbidden(t, env.serve(env.samlReq(t, http.MethodGet, "/elsewhere", session)), env.backend, 1)

	env.setRules(t, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "saml", Claims: map[string]string{"groups": "nobody-has-this"}}},
	}})
	assertForbidden(t, env.serve(env.samlReq(t, http.MethodGet, "/protected", session)), env.backend, 1)
}

func TestMiddlewareACL_AuthFailuresAreNot403(t *testing.T) {
	denyAll := []config.ACLRule{{Principals: []config.ACLPrincipal{{Mode: "basic", Subject: "alice"}}, Paths: []string{"/only-this"}}}

	env := newACLEnv(t, aclModes{basic: true, jwt: true}, denyAll, nil)

	bad := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	bad.SetBasicAuth("alice", "wrong")
	assertRejected(t, env.serve(bad), env.backend, 0, http.StatusUnauthorized, "unauthorized")
	assertRejected(t, env.serve(env.jwtReq(t, http.MethodGet, "/x", "not-a-jwt")), env.backend, 0, http.StatusUnauthorized, "unauthorized")
	assertRejected(t, env.serve(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)), env.backend, 0, http.StatusUnauthorized, "unauthorized")

	samlEnv := newACLEnv(t, aclModes{saml: true}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "saml", Subject: "someone-else"}},
	}}, nil)
	redirect := samlEnv.serve(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil))
	assert.Equal(t, http.StatusFound, redirect.Code)
	assertNotProxied(t, redirect, samlEnv.backend, 0)
}

func TestMiddlewareACL_ACSPathUnaffected(t *testing.T) {
	env := newACLEnv(t, aclModes{saml: true}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "saml", Subject: "carol@example.com"}},
		Paths:      []string{"/protected"},
	}}, nil)

	session := env.samlLogin(t) // asserts the ACS POST succeeds though no rule covers its path
	assertProxied(t, env.serve(env.samlReq(t, http.MethodGet, "/protected", session)), env.backend, 1)
}

func TestMiddlewareACL_NoAuthWithRules_DeniesEverything(t *testing.T) {
	env := newACLEnv(t, aclModes{}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "saml", Subject: "anyone"}},
	}}, nil)

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		assertForbidden(t, env.serve(httptest.NewRequestWithContext(t.Context(), m, "/", nil)), env.backend, 0)
	}
}

func TestMiddlewareACL_HotReloadFlipsDecision(t *testing.T) {
	allowAlice := []config.ACLRule{{Principals: []config.ACLPrincipal{{Mode: "basic", Subject: "alice"}}}}
	allowBob := []config.ACLRule{{Principals: []config.ACLPrincipal{{Mode: "basic", Subject: "bob"}}}}

	env := newACLEnv(t, aclModes{basic: true}, allowAlice, nil)
	assertProxied(t, env.serve(env.basicReq(t, http.MethodGet, "/", "alice")), env.backend, 1)

	env.setRules(t, allowBob)
	assertForbidden(t, env.serve(env.basicReq(t, http.MethodGet, "/", "alice")), env.backend, 1)

	env.setRules(t, allowAlice)
	assertProxied(t, env.serve(env.basicReq(t, http.MethodGet, "/", "alice")), env.backend, 2)

	env.setRules(t, nil)
	assertProxied(t, env.serve(env.basicReq(t, http.MethodGet, "/", "bob")), env.backend, 3)
}

func TestMiddlewareACL_DenyLogsAndCounts(t *testing.T) {
	logger, logs := newRecordingLogger()
	env := newACLEnv(t, aclModes{basic: true}, []config.ACLRule{{
		Principals: []config.ACLPrincipal{{Mode: "basic", Subject: "alice"}},
	}}, logger)

	before := rejectionCountByReason(t, reasonACLDenied)
	assertForbidden(t, env.serve(env.basicReq(t, http.MethodGet, "/secret", "bob")), env.backend, 0)
	assert.Equal(t, before+1, rejectionCountByReason(t, reasonACLDenied))

	why, level := logs.last(t)
	assert.Equal(t, string(reasonACLDenied), why)
	assert.Equal(t, slog.LevelInfo, level)
	attrs := logs.lastAttrs(t)
	assert.Equal(t, "bob", attrs["subject"])
	assert.Equal(t, "basic", attrs["mode"])
	assert.Equal(t, "/secret", attrs["path"])
	assert.Equal(t, http.MethodGet, attrs["method"])

	var rm metricdata.ResourceMetrics
	require.NoError(t, testMetricReader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "authn.rejections" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints { //nolint:forcetypeassert // asserted in rejectionCountByReason
				for _, kv := range dp.Attributes.ToSlice() {
					assert.Equal(t, "reason", string(kv.Key), "the metric must carry only the reason label, never the subject")
				}
			}
		}
	}
}

// lastAttrs returns every attribute of the most recent log record as
// strings.
func (h *recordingHandler) lastAttrs(t *testing.T) map[string]string {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(t, *h.records)
	out := map[string]string{}
	(*h.records)[len(*h.records)-1].Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.String()
		return true
	})
	return out
}
