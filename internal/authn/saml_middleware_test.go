package authn

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// newTestSAMLMiddleware builds a real samlsp.Middleware (via the
// production buildSAMLProvider) wired against a real TestSAMLIDP, with
// an https SPBaseURL so the SameSite=None+Secure tracker-cookie path is
// exercised — the whole point of these tests is proving the real
// wiring works end to end, not a fake.
func newTestSAMLMiddleware(t *testing.T) (mw *samlsp.Middleware, src config.SAMLSource) {
	t.Helper()
	t.Setenv("TEST_SAML_MW_SESSION_KEY", validSAMLSessionKeyForTest)

	idp := NewTestSAMLIDP(t)
	src = config.SAMLSource{
		Issuer:               idp.Issuer,
		IDPMetadataURL:       idp.MetadataURL,
		IDPMetadataCacheTTL:  time.Minute,
		SPBaseURL:            "https://proxy.example.com",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/acs",
		SessionCookie:        "saml_session",
		SessionSigningKeyEnv: "TEST_SAML_MW_SESSION_KEY",
		SessionDuration:      time.Hour,
	}
	idp.RegisterSP(src.SPEntityID, src.SPBaseURL+src.ACSPath)
	idp.SetUser("user@example.com", map[string][]string{"email": {"user@example.com"}})

	entity := testIDPMetadata(t, idp)
	m, err := buildSAMLProvider(src, entity)
	require.NoError(t, err)
	m.OnError = samlOnError(testLogger())

	return m, src
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func findCookie(resp *http.Response, prefix string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	return nil
}

func TestEnforceSAML_Unauthenticated_RedirectsWithTrackerCookie(t *testing.T) {
	mw, _ := newTestSAMLMiddleware(t)
	handler := enforceSAML(mw, okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	resp := rr.Result()
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("SAMLRequest"))

	tracker := findCookie(resp, "saml_")
	require.NotNil(t, tracker, "expected a saml_-prefixed tracker cookie to be set")
	assert.True(t, tracker.Secure, "tracker cookie must be Secure when sp_base_url is https")
	assert.Equal(t, http.SameSiteNoneMode, tracker.SameSite,
		"tracker cookie must be SameSite=None over https — see buildSAMLProvider's doc comment for the cross-site-POST bug this guards")
}

// driveIDPLogin follows redirectURL to idp's real SSO endpoint and
// extracts the SAMLResponse value from the auto-submit HTML form it
// returns. html.UnescapeString undoes html/template's attribute
// escaping (e.g. "+" -> "&#43;") — a real browser does this
// automatically via the DOM .value property before auto-submitting.
func driveIDPLogin(t *testing.T, redirectURL string) string {
	t.Helper()
	resp, err := http.Get(redirectURL) //nolint:gosec,noctx // test-only, URL is the fixture's own local server
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	m := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindStringSubmatch(string(body))
	require.Len(t, m, 2, "expected a SAMLResponse hidden form field in:\n%s", body)
	return html.UnescapeString(m[1])
}

func TestSAMLFullRoundTrip_SetsSessionCookieAndRedirectsToOriginalURI(t *testing.T) {
	mw, src := newTestSAMLMiddleware(t)
	handler := enforceSAML(mw, okHandler())

	// Step 1: unauthenticated request to an arbitrary protected URI.
	startReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", nil)
	startRR := httptest.NewRecorder()
	handler.ServeHTTP(startRR, startReq)
	startResp := startRR.Result()
	require.Equal(t, http.StatusFound, startResp.StatusCode)
	tracker := findCookie(startResp, "saml_")
	require.NotNil(t, tracker)

	// Step 2: drive the real IdP login.
	samlResponse := driveIDPLogin(t, startResp.Header.Get("Location"))
	relayState := mustQueryParam(t, startResp.Header.Get("Location"), "RelayState")

	// Step 3: POST the assertion back to the ACS endpoint, carrying the
	// tracker cookie set in step 1.
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	acsReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, src.SPBaseURL+src.ACSPath, strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsReq.AddCookie(tracker)
	acsRR := httptest.NewRecorder()
	serveACS(mw, acsRR, acsReq)

	acsResp := acsRR.Result()
	assert.Equal(t, http.StatusFound, acsResp.StatusCode)
	assert.Equal(t, "/protected/resource", acsResp.Header.Get("Location"),
		"must redirect back to the originally-requested URI, not the default")

	session := findCookie(acsResp, src.SessionCookie)
	require.NotNil(t, session, "expected the session cookie to be set")
	assert.NotEmpty(t, session.Value)

	// Step 4: the session cookie now authenticates.
	protectedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected/resource", nil)
	protectedReq.AddCookie(session)
	protectedRR := httptest.NewRecorder()
	handler.ServeHTTP(protectedRR, protectedReq)
	assert.Equal(t, http.StatusOK, protectedRR.Code)
	assert.Equal(t, "ok", protectedRR.Body.String())
}

func mustQueryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u.Query().Get(key)
}

func TestEnforceSAML_InvalidSession_RedirectsNotRejects(t *testing.T) {
	mw, src := newTestSAMLMiddleware(t)
	handler := enforceSAML(mw, okHandler())

	tests := []struct {
		name  string
		value string
	}{
		{"tampered", "not-a-valid-jwt-at-all"},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{Name: src.SessionCookie, Value: tc.value})
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code, "an invalid session must redirect to the IdP, not 401 or 200")
		})
	}
}

func TestServeACS_NeverPanics(t *testing.T) {
	mw, src := newTestSAMLMiddleware(t)
	acsURL := src.SPBaseURL + src.ACSPath

	requests := []func() *http.Request{
		func() *http.Request { return httptest.NewRequestWithContext(t.Context(), http.MethodGet, acsURL, nil) },
		func() *http.Request {
			return httptest.NewRequestWithContext(t.Context(), http.MethodPost, acsURL, strings.NewReader(""))
		},
		func() *http.Request {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, acsURL, strings.NewReader("SAMLResponse=garbage"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		},
		func() *http.Request {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, acsURL, strings.NewReader("SAMLResponse=garbage"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: src.SessionCookie, Value: "stale-session"})
			return r
		},
	}

	for i, build := range requests {
		req := build()
		rr := httptest.NewRecorder()
		assert.NotPanicsf(t, func() { serveACS(mw, rr, req) }, "request %d (%s %s) must not panic", i, req.Method, req.URL.Path)
		assert.NotEqual(t, http.StatusOK, rr.Code, "a malformed ACS request must never succeed")
	}
}

func TestRejectUnavailable(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	rejectUnavailable(rr, testLogger(), req, reasonSAMLMetadataUnavailable, assert.AnError, 30*time.Second)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Equal(t, "30", rr.Header().Get("Retry-After"))
}

// TestRejectUnavailable_RecordsRejectionMetric proves rejectUnavailable
// feeds the same authn_rejections_total counter reject does — the
// README documents saml_metadata_unavailable as one of the reasons
// exposed there, so this path must not be a silent gap. Uses the
// package-shared rejectionCountByReason/testMetricReader (see
// metrics_test.go's TestMain) rather than standing up its own
// MeterProvider — the OTel Go API only honors the first
// otel.SetMeterProvider call in the whole test binary for an
// already-created instrument like rejectionCounter, so a second,
// test-local provider here would silently observe nothing.
func TestRejectUnavailable_RecordsRejectionMetric(t *testing.T) {
	before := rejectionCountByReason(t, reasonSAMLMetadataUnavailable)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	rejectUnavailable(httptest.NewRecorder(), testLogger(), req, reasonSAMLMetadataUnavailable, assert.AnError, 30*time.Second)

	assert.Equal(t, before+1, rejectionCountByReason(t, reasonSAMLMetadataUnavailable))
}

// TestSAMLFullRoundTrip_EncryptedAssertion_DecryptsAndAuthenticates is
// the encrypted-assertion counterpart of
// TestSAMLFullRoundTrip_SetsSessionCookieAndRedirectsToOriginalURI: with
// sp_key_env/sp_cert configured and the same certificate registered
// with the fixture IdP as an encryption key, MakeAssertionEl on the IdP
// side encrypts the assertion for real (asserted directly against the
// raw decoded wire response, not just inferred from the end result
// working) and sp.ParseResponse decrypts it transparently.
func TestSAMLFullRoundTrip_EncryptedAssertion_DecryptsAndAuthenticates(t *testing.T) {
	t.Setenv("TEST_SAML_ENC_SESSION_KEY", validSAMLSessionKeyForTest)
	priv, cert := newSAMLIDPKeypair(t, true) // the SP's own keypair — must be distinct from the IdP's
	spKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	t.Setenv("TEST_SAML_ENC_SP_KEY", spKeyPEM)

	idp := NewTestSAMLIDP(t)
	src := config.SAMLSource{
		Issuer:               idp.Issuer,
		IDPMetadataURL:       idp.MetadataURL,
		IDPMetadataCacheTTL:  time.Minute,
		SPBaseURL:            "https://proxy.example.com",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/acs",
		SessionCookie:        "saml_session",
		SessionSigningKeyEnv: "TEST_SAML_ENC_SESSION_KEY",
		SessionDuration:      time.Hour,
		SPKeyEnv:             "TEST_SAML_ENC_SP_KEY",
		SPCert:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	idp.RegisterSP(src.SPEntityID, src.SPBaseURL+src.ACSPath)
	idp.RegisterSPEncryptionCert(src.SPEntityID, cert)
	idp.SetUser("user@example.com", map[string][]string{"email": {"user@example.com"}})

	mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
	require.NoError(t, err)
	mw.OnError = samlOnError(testLogger())
	handler := enforceSAML(mw, okHandler())

	startReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	startRR := httptest.NewRecorder()
	handler.ServeHTTP(startRR, startReq)
	require.Equal(t, http.StatusFound, startRR.Code)
	tracker := findCookie(startRR.Result(), "saml_")
	require.NotNil(t, tracker)

	loc := startRR.Result().Header.Get("Location")
	samlResponse := driveIDPLogin(t, loc)

	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	require.NoError(t, err)
	assert.Contains(t, string(decoded), "EncryptedAssertion", "the idp must have actually encrypted the assertion, not sent it plaintext")
	assert.NotContains(t, string(decoded), "AttributeStatement", "plaintext attributes must never appear on the wire when the assertion is encrypted")

	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {mustQueryParam(t, loc, "RelayState")}}
	acsReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, src.ACSPath, strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsReq.AddCookie(tracker)
	acsRR := httptest.NewRecorder()
	serveACS(mw, acsRR, acsReq)

	require.Equal(t, http.StatusFound, acsRR.Code, "acs must succeed: the sp must transparently decrypt the assertion")
	session := findCookie(acsRR.Result(), src.SessionCookie)
	require.NotNil(t, session, "expected the session cookie to be set after a successful decrypt")

	protectedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil)
	protectedReq.AddCookie(session)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, protectedReq)
	assert.Equal(t, http.StatusOK, rec.Code, "the decrypted assertion's session must authenticate normally")
}
