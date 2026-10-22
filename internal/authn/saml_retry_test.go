package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// newRetryTestRegistry returns a registry that builds real providers
// against a TestSAMLIDP, with a clock the test moves by hand, and a
// provider already built.
func newRetryTestRegistry(t *testing.T) (*SAMLRegistry, config.SAMLSource, *TestSAMLIDP, *time.Time) {
	t.Helper()
	t.Setenv("TEST_SAML_RETRY_SESSION_KEY", validSAMLSessionKeyForTest)

	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)
	src.SessionSigningKeyEnv = "TEST_SAML_RETRY_SESSION_KEY"
	src.IDPMetadataCacheTTL = time.Hour
	idp.RegisterSP(src.SPEntityID, src.SPBaseURL+src.ACSPath)
	idp.SetUser("user@example.com", map[string][]string{"email": {"user@example.com"}})

	r := NewSAMLRegistry(testLogger())
	t.Cleanup(r.Close)
	now := time.Now()
	r.now = func() time.Time { return now }
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)
	return r, src, idp, &now
}

// postACS starts a login through mw, has the IdP answer it, and POSTs the
// answer to the ACS path through serveACSRetrying.
func postACS(t *testing.T, r *SAMLRegistry, src config.SAMLSource, samlResponse func(loginURL string) string) *httptest.ResponseRecorder {
	t.Helper()
	mw, err := r.Provider(src)
	require.NoError(t, err)

	startRR := httptest.NewRecorder()
	enforceSAML(mw, okHandler()).ServeHTTP(startRR, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", nil))
	start := startRR.Result()
	require.Equal(t, http.StatusFound, start.StatusCode)
	tracker := findCookie(start, "saml_")
	require.NotNil(t, tracker)
	loginURL := start.Header.Get("Location")

	form := url.Values{
		"SAMLResponse": {samlResponse(loginURL)},
		"RelayState":   {mustQueryParam(t, loginURL, "RelayState")},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, src.SPBaseURL+src.ACSPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(tracker)
	rr := httptest.NewRecorder()
	serveACSRetrying(r, src, mw, rr, req)
	return rr
}

func TestServeACSRetrying_RefetchesMetadataWhenTheIDPRotatedItsKey(t *testing.T) {
	r, src, idp, now := newRetryTestRegistry(t)
	_, err := r.Provider(src) // caches the IdP's original certificate
	require.NoError(t, err)

	idp.Rotate(t)
	*now = now.Add(2 * time.Minute) // past the minimum refetch interval, far inside the ttl

	rr := postACS(t, r, src, func(loginURL string) string { return driveIDPLogin(t, loginURL) })

	assert.Equal(t, http.StatusFound, rr.Code, "the retry against the refetched metadata must succeed")
	assert.NotNil(t, findCookie(rr.Result(), src.SessionCookie), "expected the session cookie to be set")
}

func TestServeACSRetrying_DoesNotRefetchMoreThanOncePerMinute(t *testing.T) {
	r, src, idp, _ := newRetryTestRegistry(t)
	_, err := r.Provider(src)
	require.NoError(t, err)

	idp.Rotate(t) // the clock hasn't moved: the metadata was fetched just now

	rr := postACS(t, r, src, func(loginURL string) string { return driveIDPLogin(t, loginURL) })

	assert.Equal(t, http.StatusForbidden, rr.Code, "a refetch inside the minimum interval is not allowed")
}

func TestServeACSRetrying_AnAssertionThatIsStillBadAfterTheRefetchIsRejected(t *testing.T) {
	r, src, _, now := newRetryTestRegistry(t)
	_, err := r.Provider(src)
	require.NoError(t, err)
	*now = now.Add(2 * time.Minute)
	fetchedBefore := r.fetchedAt

	rr := postACS(t, r, src, func(string) string { return "bm90IGEgU0FNTCByZXNwb25zZQ==" })

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "forbidden", rr.Body.String())
	assert.True(t, r.fetchedAt.After(fetchedBefore), "the failed callback should have caused one refetch")
}

func TestSAMLRegistry_Provider_FailedRefreshBacksOffBeyondAMinute(t *testing.T) {
	r, src, idp, now := newRetryTestRegistry(t)
	src.IDPMetadataCacheTTL = 10 * time.Minute
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)
	p1, err := r.Provider(src)
	require.NoError(t, err)

	idp.Server.Close() // the metadata endpoint is now unreachable
	*now = now.Add(11 * time.Minute)
	p2, err := r.Provider(src)
	require.NoError(t, err, "a failed refresh keeps serving the previous provider")
	assert.Same(t, p1, p2)
	failedAt := r.fetchedAt

	*now = now.Add(2 * time.Minute) // not yet past the failure backoff
	_, err = r.Provider(src)
	require.NoError(t, err)
	assert.Equal(t, failedAt, r.fetchedAt, "no new attempt inside the backoff")

	*now = now.Add(4 * time.Minute) // past it
	_, err = r.Provider(src)
	require.NoError(t, err)
	assert.True(t, r.fetchedAt.After(failedAt), "a new attempt once the backoff has passed")
}
