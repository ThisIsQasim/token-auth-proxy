package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// fakeSource is a ConfigSource test double, mirroring
// internal/proxy/proxy_test.go's fakeSource — its own copy since
// internal/authn deliberately doesn't import internal/proxy (see
// ConfigSource's doc comment in authn.go).
type fakeSource struct {
	tb      testing.TB
	current atomic.Pointer[config.Config]
}

func newFakeSource(tb testing.TB, cfg *config.Config) *fakeSource {
	tb.Helper()
	s := &fakeSource{tb: tb}
	s.set(cfg)
	return s
}

func (s *fakeSource) Current() *config.Config { return s.current.Load() }

// set validates cfg (matching the last step of the real
// file/flag/env pipeline) and publishes it. Unlike production's
// internal/config.decode, this does not also call the package-internal
// applyDefaults first — that's unexported outside internal/config — so
// callers must pre-populate anything a real load would have defaulted
// that the test actually depends on (e.g. jwtSourceFor sets Credentials
// explicitly, matching JWTSource.applyDefaults' default).
func (s *fakeSource) set(cfg *config.Config) {
	s.tb.Helper()
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	if cfg.Target == "" {
		cfg.Target = "http://127.0.0.1:1" // unused by these tests; only Validate cares it's well-formed
	}
	require.NoError(s.tb, cfg.Validate())
	s.current.Store(cfg)
}

// backendStub is a minimal downstream handler standing in for the
// reverse proxy — these tests only need to know whether the middleware
// let a request through and what it looked like when it arrived, not
// exercise real proxying (that's internal/proxy/proxy_test.go's job).
type backendStub struct {
	hits          atomic.Int64
	lastAuthValue atomic.Value // string
}

func (b *backendStub) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.lastAuthValue.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (b *backendStub) Hits() int { return int(b.hits.Load()) }

// backendBody is what backendStub answers with. Every assertion below
// checks it rather than the status alone: a bare 200 proves only that
// *something* answered, and a bare 401 proves only that something
// refused — neither says whether the response the client actually got
// came from the backend or from the proxy. Since deciding that is the
// entire job of this middleware, every test states which one it
// expected.
const backendBody = "ok"

// assertProxied asserts the request reached the backend wantHits times
// and that the backend's own response came back to the client
// unchanged.
func assertProxied(t *testing.T, rec *httptest.ResponseRecorder, backend *backendStub, wantHits int) {
	t.Helper()
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, wantHits, backend.Hits())
	assert.Equal(t, backendBody, rec.Body.String(), "the backend's own response must reach the client unchanged")
}

// assertNotProxied asserts this request didn't reach the backend —
// wantHits is the running total for the test, which is 0 in all but the
// few tests that make an allowed request first — and that whatever the
// client got back didn't come from the backend either.
func assertNotProxied(t *testing.T, rec *httptest.ResponseRecorder, backend *backendStub, wantHits int) {
	t.Helper()
	assert.Equal(t, wantHits, backend.Hits(), "backend must not be reached")
	assert.NotEqual(t, backendBody, rec.Body.String(), "the client must not receive the backend's response")
}

// assertRejected is assertNotProxied plus the proxy's own status and
// body — spelled out to pin the "never explain why" rule from reason's
// doc comment in authn.go.
func assertRejected(t *testing.T, rec *httptest.ResponseRecorder, backend *backendStub, wantHits, wantStatus int, wantBody string) {
	t.Helper()
	assert.Equal(t, wantStatus, rec.Code)
	assert.Equal(t, wantBody, rec.Body.String())
	assertNotProxied(t, rec, backend, wantHits)
}

// assertRedirected asserts the request was sent to the IdP instead of
// the backend. Unlike assertRejected the body isn't a fixed string
// (samlsp writes its own), so only assertNotProxied's check applies.
func assertRedirected(t *testing.T, rec *httptest.ResponseRecorder, backend *backendStub, wantHits int) {
	t.Helper()
	assert.Equal(t, http.StatusFound, rec.Code)
	assertNotProxied(t, rec, backend, wantHits)
}

// jwtSourceFor builds a JWTSource trusting idp, with Algorithms and
// Credentials set explicitly to what JWTSource.applyDefaults would
// have produced — fakeSource.set doesn't call applyDefaults (see its
// doc comment), so tests that need those defaults set them here.
func jwtSourceFor(idp *TestIDP) config.JWTSource {
	return config.JWTSource{
		Name:        idp.Issuer,
		Issuer:      idp.Issuer,
		JWKSURL:     idp.JWKSURL,
		Algorithms:  []string{"RS256"},
		Credentials: []config.CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}},
	}
}

// newTestMiddleware wires NewMiddleware with a fresh SAMLRegistry and
// BasicRegistry — most tests in this file only care about the JWT leg,
// so this avoids repeating that construction/cleanup boilerplate at
// every call site. Tests exercising the SAML leg or the composition
// between legs build their own instead (see TestMiddleware_SAMLOnly_*
// and TestMiddleware_Composition_*).
func newTestMiddleware(t *testing.T, source ConfigSource, reg *Registry) func(http.Handler) http.Handler {
	t.Helper()
	samlReg := NewSAMLRegistry(testLogger())
	t.Cleanup(samlReg.Close)
	return NewMiddleware(source, reg, samlReg, NewBasicRegistry(testLogger()), testLogger())
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// samlSourceFor builds a SAMLSource trusting idp and registers proxyBase
// (+ acsPath) as idp's recognized SP, mirroring jwtSourceFor's role for
// the SAML leg of these composition tests.
func samlSourceFor(t *testing.T, idp *TestSAMLIDP, sessionKeyEnv string) config.SAMLSource {
	t.Helper()
	const proxyBase = "https://proxy.example.com"
	const acsPath = "/saml/acs"
	src := config.SAMLSource{
		Name:                 "saml-a",
		Issuer:               idp.Issuer,
		IDPMetadataURL:       idp.MetadataURL,
		IDPMetadataCacheTTL:  time.Minute,
		SPBaseURL:            proxyBase,
		SPEntityID:           proxyBase + "/saml/metadata",
		ACSPath:              acsPath,
		SessionCookie:        "saml_a_session",
		SessionSigningKeyEnv: sessionKeyEnv,
		SessionDuration:      time.Hour,
	}
	idp.RegisterSP(src.SPEntityID, proxyBase+acsPath)
	return src
}

func TestMiddleware_SAMLOnly_UnauthenticatedRedirects(t *testing.T) {
	t.Setenv("MIDDLEWARE_TEST_SAML_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	idp.SetUser("user@example.com", nil)
	src := samlSourceFor(t, idp, "MIDDLEWARE_TEST_SAML_KEY")

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}})
	require.True(t, source.Current().Inbound.Auth.Enabled())
	require.False(t, source.Current().Inbound.Auth.JWTEnabled())
	require.True(t, source.Current().Inbound.Auth.SAMLEnabled())

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, ""))

	assertRedirected(t, rec, backend, 0)
}

func TestMiddleware_NoAuthConfigured_PassesThrough(t *testing.T) {
	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, ""))

	assertProxied(t, rec, backend, 1)
}

func TestMiddleware_AllJWTSourcesDisabled_PassesThrough(t *testing.T) {
	idp := NewTestIDP(t)
	src := jwtSourceFor(idp)
	src.Disabled = true

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, ""))

	assertProxied(t, rec, backend, 1)
}

func TestMiddleware_ValidToken_ForwardedUnmodified(t *testing.T) {
	idp := NewTestIDP(t)
	src := jwtSourceFor(idp)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, token))

	assertProxied(t, rec, backend, 1)
	assert.Equal(t, "Bearer "+token, backend.lastAuthValue.Load())
}

func TestMiddleware_MissingToken_Rejected(t *testing.T) {
	idp := NewTestIDP(t)
	src := jwtSourceFor(idp)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, ""))

	assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_BadToken_Rejected(t *testing.T) {
	idp := NewTestIDP(t)
	src := jwtSourceFor(idp)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, "not-a-valid-jwt"))

	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_UnknownIssuer_Rejected(t *testing.T) {
	idp := NewTestIDP(t)
	other := NewTestIDP(t, WithIssuer("https://unconfigured-issuer.example.com"))
	src := jwtSourceFor(idp)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	token := other.Sign(t, jwt.RegisteredClaims{Issuer: other.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, token))

	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_MuxWiring_HealthzStaysUnauthenticated(t *testing.T) {
	idp := NewTestIDP(t)
	src := jwtSourceFor(idp)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{src}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/", mw(backend.Handler()))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	assertRejected(t, rec2, backend, 0, http.StatusUnauthorized, "unauthorized")
}

// TestMiddleware_HotReloadSwapsTrustedIssuer proves the end-to-end
// interaction between Registry.Reconcile and the middleware across a
// live config swap — token A works while A is trusted, stops working
// (and B starts) the moment the source list changes, with no process
// restart.
func TestMiddleware_HotReloadSwapsTrustedIssuer(t *testing.T) {
	idpA := NewTestIDP(t, WithIssuer("https://a.example.com"))
	idpB := NewTestIDP(t, WithIssuer("https://b.example.com"))
	idpB.Rotate(t) // ensure A and B have genuinely distinct keys, not just labels

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{jwtSourceFor(idpA)}}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)
	handler := mw(backend.Handler())

	tokenA := idpA.Sign(t, jwt.RegisteredClaims{Issuer: idpA.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	tokenB := idpB.Sign(t, jwt.RegisteredClaims{Issuer: idpB.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, tokenA))
	assertProxied(t, rec, backend, 1) // token A works while A is trusted

	// Swap the trusted source from A to B.
	source.set(&config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{jwtSourceFor(idpB)}}}})

	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, bearerRequest(t, tokenA))
	// Token A must stop working once A is no longer trusted — and the
	// backend must not have been reached again (still 1 hit).
	assertRejected(t, recA, backend, 1, http.StatusUnauthorized, "unauthorized")

	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, bearerRequest(t, tokenB))
	assertProxied(t, recB, backend, 2) // token B works once B is trusted
}

// --- composition matrix: JWT and SAML enabled together ---
//
// See NewMiddleware's doc comment for the precedence order these
// exercise: a presented (even bad) bearer token is JWT's alone to
// decide; only a genuinely credential-less request ever reaches SAML;
// the ACS path is dispatched before either leg's enforcement runs.

// newCombinedMiddleware builds a JWT+SAML config sharing one backend,
// with a real TestSAMLIDP (so a successful metadata fetch is the
// default) and a real TestIDP.
func newCombinedMiddleware(t *testing.T) (handler http.Handler, backend *backendStub, jwtIDP *TestIDP, samlSrc config.SAMLSource) {
	t.Helper()
	t.Setenv("MIDDLEWARE_COMPOSITION_SAML_KEY", validSAMLSessionKeyForTest)

	jwtIDP = NewTestIDP(t)
	jwtSrc := jwtSourceFor(jwtIDP)

	samlIDP := NewTestSAMLIDP(t)
	samlIDP.SetUser("user@example.com", nil)
	samlSrc = samlSourceFor(t, samlIDP, "MIDDLEWARE_COMPOSITION_SAML_KEY")

	backend = &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		JWT:  []config.JWTSource{jwtSrc},
		SAML: &samlSrc,
	}}})
	require.True(t, source.Current().Inbound.Auth.JWTEnabled())
	require.True(t, source.Current().Inbound.Auth.SAMLEnabled())

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	return mw(backend.Handler()), backend, jwtIDP, samlSrc
}

func TestMiddleware_Composition_ValidJWT_ForwardsWithoutConsultingSAML(t *testing.T) {
	handler, backend, jwtIDP, _ := newCombinedMiddleware(t)

	token := jwtIDP.Sign(t, jwt.RegisteredClaims{Issuer: jwtIDP.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, token))

	assertProxied(t, rec, backend, 1)
	assert.Empty(t, rec.Result().Cookies(), "a valid bearer token must never involve the SAML leg at all")
}

func TestMiddleware_Composition_BadJWT_RejectsWithoutFallingThroughToSAML(t *testing.T) {
	handler, backend, _, _ := newCombinedMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, "not-a-valid-jwt"))

	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
	assert.Empty(t, rec.Result().Cookies(), "a presented-but-invalid bearer token must be JWT's final answer, not redirected to SAML")
}

func TestMiddleware_Composition_NoCredential_FallsThroughToSAMLRedirect(t *testing.T) {
	handler, backend, _, _ := newCombinedMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, ""))

	assertRedirected(t, rec, backend, 0) // a genuinely credential-less request falls through to SAML, not JWT's 401
}

func TestMiddleware_Composition_ValidSAMLSession_Forwards(t *testing.T) {
	handler, backend, _, samlSrc := newCombinedMiddleware(t)

	// Drive step 1 to get a genuine tracker cookie + redirect, matching
	// saml_middleware_test.go's full-round-trip pattern.
	startReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	startRR := httptest.NewRecorder()
	handler.ServeHTTP(startRR, startReq)
	require.Equal(t, http.StatusFound, startRR.Code)
	tracker := findCookie(startRR.Result(), "saml_")
	require.NotNil(t, tracker)

	samlResponse := driveIDPLogin(t, startRR.Result().Header.Get("Location"))
	relayState := mustQueryParam(t, startRR.Result().Header.Get("Location"), "RelayState")

	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, samlSrc.ACSPath, strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsReq.AddCookie(tracker)
	acsRR := httptest.NewRecorder()
	handler.ServeHTTP(acsRR, acsReq)
	require.Equal(t, http.StatusFound, acsRR.Code, "the acs path must be dispatched even with JWT also enabled")
	session := findCookie(acsRR.Result(), samlSrc.SessionCookie)
	require.NotNil(t, session)

	protectedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	protectedReq.AddCookie(session)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, protectedReq)

	assertProxied(t, rec, backend, 1) // a valid saml session forwards, with no bearer token presented
}

func TestMiddleware_Composition_ACSPath_NeverIntercepted(t *testing.T) {
	handler, backend, _, samlSrc := newCombinedMiddleware(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, samlSrc.ACSPath, strings.NewReader(""))
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() { handler.ServeHTTP(rec, req) },
		"the acs path must dispatch to serveACS before either leg's enforcement runs, which is what avoids samlsp's RequireAccount-on-ACS-path panic")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "a bare acs POST must not be treated as JWT's no-credential case")
	assertNotProxied(t, rec, backend, 0)
}

func TestMiddleware_Composition_SAMLMetadataUnavailable_ServiceUnavailable(t *testing.T) {
	t.Setenv("MIDDLEWARE_COMPOSITION_SAML_KEY_2", validSAMLSessionKeyForTest)
	jwtIDP := NewTestIDP(t)
	jwtSrc := jwtSourceFor(jwtIDP)

	samlSrc := config.SAMLSource{
		Name:                 "saml-a",
		Issuer:               "https://unreachable-idp.invalid/metadata",
		IDPMetadataURL:       "https://unreachable-idp.invalid/metadata",
		SPBaseURL:            "https://proxy.example.com",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/acs",
		SessionCookie:        "saml_a_session",
		SessionSigningKeyEnv: "MIDDLEWARE_COMPOSITION_SAML_KEY_2",
	}

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		JWT:  []config.JWTSource{jwtSrc},
		SAML: &samlSrc,
	}}})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	handler := newTestMiddleware(t, source, reg)(backend.Handler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, "")) // no credential -> falls through to the (unreachable) SAML leg

	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assertRejected(t, rec, backend, 0, http.StatusServiceUnavailable, "service unavailable")
}

// --- Basic auth leg ------------------------------------------------
//
// See NewMiddleware's doc comment for the precedence these exercise:
// a presented Basic credential is Basic's alone to decide, ahead of
// JWT; only a credential-less request reaches SAML or the combined
// no-credential 401.

// newBasicMiddleware wires a Basic-only config, returning the handler
// and the backend it fronts.
func newBasicMiddleware(t *testing.T, extra ...config.JWTSource) (http.Handler, *backendStub) {
	t.Helper()

	basicSrc := basicSourceFor(t)
	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		JWT:   extra,
		Basic: &basicSrc,
	}}})

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	return newTestMiddleware(t, source, reg)(backend.Handler()), backend
}

func basicRequest(t *testing.T, username, password string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.SetBasicAuth(username, password)
	return r
}

func TestMiddleware_BasicOnly_ValidCredentialForwards(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, basicRequest(t, "alice", "hunter2"))

	assertProxied(t, rec, backend, 1)
	assert.NotEmpty(t, backend.lastAuthValue.Load(),
		"the Authorization header is forwarded unchanged, like every other leg")
}

func TestMiddleware_BasicOnly_BadPasswordRejects(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, basicRequest(t, "alice", "wrong"))

	assert.Equal(t, `Basic realm="test-realm", charset="UTF-8"`, rec.Header().Get("WWW-Authenticate"))
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_BasicOnly_NoCredentialChallenges(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, `Basic realm="test-realm", charset="UTF-8"`, rec.Header().Get("WWW-Authenticate"))
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_BasicOnly_MalformedHeaderRejects(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic not-valid-base64!!")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_BasicOnly_OtherSchemePassesThroughToNoCredential(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Digest username=alice")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Not Basic-shaped, so it's treated as no credential at all rather
	// than as a malformed Basic one.
	assert.Equal(t, `Basic realm="test-realm", charset="UTF-8"`, rec.Header().Get("WWW-Authenticate"))
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}

func TestMiddleware_Composition_BasicCredentialDecidesBeforeJWT(t *testing.T) {
	idp := NewTestIDP(t)
	jwtSrc := jwtSourceFor(idp)
	// A JWT source reading the same header with no prefix: without
	// Basic taking the request first, this would extract the Basic
	// credential and reject it as a malformed token. (config.Validate
	// rejects this pairing outright; fakeSource.set runs Validate, so
	// the source is staged as disabled to get it past that and still
	// exercise the middleware ordering.)
	jwtSrc.Credentials = []config.CredentialLocation{{Location: "header", Name: "Authorization"}}
	jwtSrc.Disabled = true

	handler, backend := newBasicMiddleware(t, jwtSrc)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, basicRequest(t, "alice", "hunter2"))

	assertProxied(t, rec, backend, 1)
}

func TestMiddleware_Composition_BasicAndJWT_NoCredentialOffersBothChallenges(t *testing.T) {
	idp := NewTestIDP(t)
	handler, backend := newBasicMiddleware(t, jwtSourceFor(idp))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
	assert.Equal(t, []string{`Basic realm="test-realm", charset="UTF-8"`, "Bearer"},
		rec.Header().Values("WWW-Authenticate"),
		"a credential-less request is answerable by either scheme, so both are offered")
}

func TestMiddleware_Composition_BasicAndJWT_BearerTokenStillReachesJWT(t *testing.T) {
	idp := NewTestIDP(t)
	handler, backend := newBasicMiddleware(t, jwtSourceFor(idp))

	token := idp.Sign(t, jwt.RegisteredClaims{Issuer: idp.Issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, token))

	assertProxied(t, rec, backend, 1)
}

func TestMiddleware_Composition_BasicAndSAML_ACSPathIsStillDispatchedFirst(t *testing.T) {
	t.Setenv("MIDDLEWARE_BASIC_SAML_KEY", validSAMLSessionKeyForTest)

	samlIDP := NewTestSAMLIDP(t)
	samlIDP.SetUser("user@example.com", nil)
	samlSrc := samlSourceFor(t, samlIDP, "MIDDLEWARE_BASIC_SAML_KEY")
	basicSrc := basicSourceFor(t)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		SAML:  &samlSrc,
		Basic: &basicSrc,
	}}})

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	handler := newTestMiddleware(t, source, reg)(backend.Handler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, samlSrc.ACSPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"the ACS callback must never be answered with a Basic challenge")
	assertNotProxied(t, rec, backend, 0)
}

func TestMiddleware_Composition_BasicAndSAML_CredentiallessRequestRedirects(t *testing.T) {
	t.Setenv("MIDDLEWARE_BASIC_SAML_REDIRECT_KEY", validSAMLSessionKeyForTest)

	samlIDP := NewTestSAMLIDP(t)
	samlIDP.SetUser("user@example.com", nil)
	samlSrc := samlSourceFor(t, samlIDP, "MIDDLEWARE_BASIC_SAML_REDIRECT_KEY")
	basicSrc := basicSourceFor(t)

	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{
		SAML:  &samlSrc,
		Basic: &basicSrc,
	}}})

	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	handler := newTestMiddleware(t, source, reg)(backend.Handler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// Documented consequence of SAML's step preceding the combined
	// challenge: with SAML enabled, Basic only serves clients that send
	// the header proactively — there's no browser password prompt.
	assertRedirected(t, rec, backend, 0)
	assert.Empty(t, rec.Header().Values("WWW-Authenticate"))

	// A proactively-presented Basic credential is still honored.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, basicRequest(t, "alice", "hunter2"))
	assertProxied(t, rec, backend, 1)
}

func TestMiddleware_BasicOnly_UnknownUserRejects(t *testing.T) {
	handler, backend := newBasicMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, basicRequest(t, "mallory", "hunter2"))

	assert.Equal(t, `Basic realm="test-realm", charset="UTF-8"`, rec.Header().Get("WWW-Authenticate"),
		"an unknown user is answered identically to a wrong password")
	assertRejected(t, rec, backend, 0, http.StatusUnauthorized, "unauthorized")
}
