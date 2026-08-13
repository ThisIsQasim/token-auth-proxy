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

// newTestMiddleware wires NewMiddleware with a fresh SAMLRegistry —
// most tests in this file only care about the JWT leg, so this avoids
// repeating the SAMLRegistry construction/cleanup boilerplate at every
// call site. Tests exercising the SAML leg or the composition between
// the two build their own instead (see TestMiddleware_SAMLOnly_* and
// TestMiddleware_Composition_*).
func newTestMiddleware(t *testing.T, source ConfigSource, reg *Registry) func(http.Handler) http.Handler {
	t.Helper()
	samlReg := NewSAMLRegistry(testLogger())
	t.Cleanup(samlReg.Close)
	return NewMiddleware(source, reg, samlReg, testLogger())
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

	assert.Equal(t, http.StatusFound, rec.Code, "a SAML-only config must redirect an unauthenticated request to the IdP, not pass it through")
	assert.Equal(t, 0, backend.Hits())
}

func TestMiddleware_NoAuthConfigured_PassesThrough(t *testing.T) {
	backend := &backendStub{}
	source := newFakeSource(t, &config.Config{})
	reg := NewRegistry(testLogger())
	t.Cleanup(reg.Close)
	mw := newTestMiddleware(t, source, reg)

	rec := httptest.NewRecorder()
	mw(backend.Handler()).ServeHTTP(rec, bearerRequest(t, ""))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, backend.Hits())
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

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, backend.Hits())
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

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, backend.Hits())
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

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
	assert.Equal(t, 0, backend.Hits(), "backend must never be reached on rejection")
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

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
	assert.Equal(t, 0, backend.Hits())
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

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, backend.Hits())
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
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
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
	require.Equal(t, http.StatusOK, rec.Code, "token A must work while A is trusted")

	// Swap the trusted source from A to B.
	source.set(&config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{JWT: []config.JWTSource{jwtSourceFor(idpB)}}}})

	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, bearerRequest(t, tokenA))
	assert.Equal(t, http.StatusUnauthorized, recA.Code, "token A must stop working once A is no longer trusted")

	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, bearerRequest(t, tokenB))
	assert.Equal(t, http.StatusOK, recB.Code, "token B must work once B is trusted")
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

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, backend.Hits())
	assert.Empty(t, rec.Result().Cookies(), "a valid bearer token must never involve the SAML leg at all")
}

func TestMiddleware_Composition_BadJWT_RejectsWithoutFallingThroughToSAML(t *testing.T) {
	handler, backend, _, _ := newCombinedMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, "not-a-valid-jwt"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "a presented-but-invalid bearer token must be JWT's final answer, not redirected to SAML")
	assert.Equal(t, 0, backend.Hits())
	assert.Empty(t, rec.Result().Cookies())
}

func TestMiddleware_Composition_NoCredential_FallsThroughToSAMLRedirect(t *testing.T) {
	handler, backend, _, _ := newCombinedMiddleware(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(t, ""))

	assert.Equal(t, http.StatusFound, rec.Code, "a genuinely credential-less request must fall through to SAML's redirect, not JWT's 401")
	assert.Equal(t, 0, backend.Hits())
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

	assert.Equal(t, http.StatusOK, rec.Code, "a valid saml session must forward, with no bearer token presented")
	assert.Equal(t, 1, backend.Hits())
}

func TestMiddleware_Composition_ACSPath_NeverIntercepted(t *testing.T) {
	handler, _, _, samlSrc := newCombinedMiddleware(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, samlSrc.ACSPath, strings.NewReader(""))
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() { handler.ServeHTTP(rec, req) },
		"the acs path must dispatch to serveACS before either leg's enforcement runs, which is what avoids samlsp's RequireAccount-on-ACS-path panic")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "a bare acs POST must not be treated as JWT's no-credential case")
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

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, 0, backend.Hits())
}
