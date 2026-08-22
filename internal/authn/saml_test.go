package authn

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

func newTestSAMLRegistry(t *testing.T, newProvider newSAMLProviderFunc) *SAMLRegistry {
	t.Helper()
	r := NewSAMLRegistry(testLogger())
	t.Cleanup(r.Close)
	r.newProvider = newProvider
	return r
}

// samlProviderCall records one call made to a fakeNewSAMLProvider.
type samlProviderCall struct {
	src config.SAMLSource
}

// newFakeSAMLProvider returns a newSAMLProviderFunc that records every
// call and either succeeds (returning a distinct *samlsp.Middleware
// each time, so tests can tell rebuilds apart by pointer identity) or
// fails according to shouldFail — never touching the network or any
// real XML-DSig machinery, matching newFakeNewKeyfunc's identical role
// in jwks_test.go.
func newFakeSAMLProvider(calls *[]samlProviderCall, mu *sync.Mutex, shouldFail func(config.SAMLSource) error) newSAMLProviderFunc {
	return func(src config.SAMLSource, _ *saml.EntityDescriptor) (*samlsp.Middleware, error) {
		mu.Lock()
		*calls = append(*calls, samlProviderCall{src: src})
		mu.Unlock()
		if shouldFail != nil {
			if err := shouldFail(src); err != nil {
				return nil, err
			}
		}
		return &samlsp.Middleware{}, nil
	}
}

// testSAMLSource returns a SAMLSource pointed at idp's real metadata
// endpoint — fetchIDPMetadata is never faked (unlike newSAMLProviderFunc),
// so every SAMLRegistry test exercises a real HTTP fetch against a real
// TestSAMLIDP, same as jwks_test.go's OIDC-discovery tests do against
// NewTestIDP.
func testSAMLSource(idp *TestSAMLIDP) config.SAMLSource {
	return config.SAMLSource{
		Issuer:               idp.Issuer,
		IDPMetadataURL:       idp.MetadataURL,
		IDPMetadataCacheTTL:  time.Minute,
		SPBaseURL:            "https://proxy.example.com",
		SPEntityID:           "https://proxy.example.com/saml/metadata",
		ACSPath:              "/saml/acs",
		SessionCookie:        "saml_session",
		SessionSigningKeyEnv: "TEST_SAML_SESSION_KEY", // never read: newProvider is faked in these tests
		SessionDuration:      time.Hour,
	}
}

func TestSAMLRegistry_Reconcile_SamePointerIsNoOp(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src := testSAMLSource(idp)
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}

	for i := 0; i < 5; i++ {
		r.Reconcile(cfg)
	}
	_, err := r.Provider(src)
	require.NoError(t, err)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "repeated Reconcile calls on the same pointer must not rebuild")
}

func TestSAMLRegistry_Reconcile_ContentIdenticalNewPointer_NoRebuild(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src := testSAMLSource(idp)
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}

	r.Reconcile(cfg1)
	_, err := r.Provider(src)
	require.NoError(t, err)

	r.Reconcile(cfg2) // different pointer, identical content/fingerprint
	_, err = r.Provider(src)
	require.NoError(t, err)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "content-identical reconcile must not rebuild the provider")
}

func TestSAMLRegistry_Reconcile_FieldChanged_Rebuilds(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src1 := testSAMLSource(idp)
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src1}}}
	r.Reconcile(cfg1)
	p1, err := r.Provider(src1)
	require.NoError(t, err)

	src2 := src1
	src2.SessionCookie = "different_cookie"
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src2}}}
	r.Reconcile(cfg2)
	p2, err := r.Provider(src2)
	require.NoError(t, err)

	assert.NotSame(t, p1, p2, "a fingerprint field change must produce a new provider")
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n)
}

// TestSAMLRegistry_Reconcile_SPCertChanged_Rebuilds is a dedicated
// regression test for a real bug found in review: samlFingerprint
// initially omitted SPKeyEnv/SPCert entirely, so rotating (or
// adding/removing) the SP's persistent keypair via config never
// triggered a rebuild — the old provider (built with the old, possibly
// compromised, key) kept being served until an unrelated TTL-driven
// refresh happened to rebuild it anyway.
func TestSAMLRegistry_Reconcile_SPCertChanged_Rebuilds(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src1 := testSAMLSource(idp)
	src1.SPKeyEnv = "TEST_SAML_SP_KEY_ENV_NAME" // never read: newProvider is faked in this test
	src1.SPCert = "cert-v1"
	cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src1}}}
	r.Reconcile(cfg1)
	p1, err := r.Provider(src1)
	require.NoError(t, err)

	src2 := src1
	src2.SPCert = "cert-v2" // simulates rotating to a new cert (and, in practice, a new key behind SPKeyEnv)
	cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src2}}}
	r.Reconcile(cfg2)
	p2, err := r.Provider(src2)
	require.NoError(t, err)

	assert.NotSame(t, p1, p2, "changing sp_cert must produce a new provider, not keep serving the one built with the old key")
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n)
}

func TestSAMLRegistry_Reconcile_DisabledOrRemoved_Evicts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(cfg *config.Config)
	}{
		{"removed", func(cfg *config.Config) { cfg.Inbound.Auth.SAML = nil }},
		{"disabled", func(cfg *config.Config) { cfg.Inbound.Auth.SAML.Disabled = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []samlProviderCall
			r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
			idp := NewTestSAMLIDP(t)

			src := testSAMLSource(idp)
			cfg1 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
			r.Reconcile(cfg1)
			_, err := r.Provider(src)
			require.NoError(t, err)

			src2 := src
			cfg2 := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src2}}}
			tc.mutate(cfg2)
			r.Reconcile(cfg2)

			r.mu.Lock()
			p := r.provider
			r.mu.Unlock()
			assert.Nil(t, p, "the built provider must be dropped once the source is disabled or removed")
		})
	}
}

func TestSAMLRegistry_Provider_BuildFailureIsNegativelyCached(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	buildErr := errors.New("idp unreachable")
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, func(config.SAMLSource) error { return buildErr }))
	idp := NewTestSAMLIDP(t)

	now := time.Now()
	r.now = func() time.Time { return now }
	r.retry = time.Minute

	src := testSAMLSource(idp)
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)

	_, err1 := r.Provider(src)
	require.Error(t, err1)
	_, err2 := r.Provider(src)
	require.Error(t, err2)

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "a second call within the retry window must not attempt another build")

	now = now.Add(2 * time.Minute) // advance past the retry window
	_, err3 := r.Provider(src)
	require.Error(t, err3)

	mu.Lock()
	n = len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "a call after the retry window must attempt another build")
}

func TestSAMLRegistry_Provider_TTLExpiry_TriggersRefresh(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	now := time.Now()
	r.now = func() time.Time { return now }

	src := testSAMLSource(idp)
	src.IDPMetadataCacheTTL = time.Minute
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)

	p1, err := r.Provider(src)
	require.NoError(t, err)

	// Still within the TTL: no refresh.
	_, err = r.Provider(src)
	require.NoError(t, err)
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "a call within the metadata TTL must not refetch")

	now = now.Add(2 * time.Minute) // advance past IDPMetadataCacheTTL
	p2, err := r.Provider(src)
	require.NoError(t, err)

	assert.NotSame(t, p1, p2, "a TTL-expiry refresh must produce a new provider")
	mu.Lock()
	n = len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "TTL expiry must trigger exactly one refresh build")
}

func TestSAMLRegistry_Provider_FailedRefreshKeepsServingStale(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	var shouldFail bool
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, func(config.SAMLSource) error {
		if shouldFail {
			return errors.New("idp metadata endpoint down")
		}
		return nil
	}))
	idp := NewTestSAMLIDP(t)

	now := time.Now()
	r.now = func() time.Time { return now }

	src := testSAMLSource(idp)
	src.IDPMetadataCacheTTL = time.Minute
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)

	p1, err := r.Provider(src)
	require.NoError(t, err)

	now = now.Add(2 * time.Minute) // advance past IDPMetadataCacheTTL
	shouldFail = true

	p2, err := r.Provider(src)
	require.NoError(t, err, "a refresh failure must not surface as an error to an already-working registry")
	assert.Same(t, p1, p2, "a refresh failure must keep serving the previous provider")

	// Immediately calling again must not hammer the (still down) IdP —
	// the TTL clock resets on a failed refresh attempt.
	_, err = r.Provider(src)
	require.NoError(t, err)
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 2, n, "a failed refresh must reset the retry clock rather than retry every request")
}

func TestSAMLRegistry_Provider_ConcurrentCallsBuildOnce(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src := testSAMLSource(idp)
	cfg := &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{SAML: &src}}}
	r.Reconcile(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Provider(src)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	mu.Lock()
	n := len(calls)
	mu.Unlock()
	assert.Equal(t, 1, n, "a concurrent burst must serialize on a single build")
}

func TestSAMLRegistry_Close_CancelsFutureFetches(t *testing.T) {
	var mu sync.Mutex
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, &mu, nil))
	idp := NewTestSAMLIDP(t)

	src := testSAMLSource(idp)
	r.Close()

	_, err := r.Provider(src)
	require.Error(t, err, "a fetch bound to an already-canceled registry context must fail")
}

// TestSAMLRegistry_Provider_WiresOnError proves fetchAndBuild's OnError
// wiring actually takes effect — using the real buildSAMLProvider (not
// the fake), so this exercises the exact path production uses, not
// just the seam. Without it, samlsp's DefaultOnError would silently be
// used instead, bypassing structured logging entirely (see
// fetchAndBuild's doc comment for why this can't be caught by
// buildSAMLProvider's own unit tests, which never touch a Registry).
func TestSAMLRegistry_Provider_WiresOnError(t *testing.T) {
	t.Setenv("TEST_SAML_ONERROR_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	r := NewSAMLRegistry(testLogger())
	t.Cleanup(r.Close)

	src := testSAMLSource(idp)
	src.SessionSigningKeyEnv = "TEST_SAML_ONERROR_KEY"
	mw, err := r.Provider(src)
	require.NoError(t, err)

	require.NotNil(t, mw.OnError)
	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	mw.OnError(rr, req, errors.New("boom"))
	assert.Equal(t, http.StatusForbidden, rr.Code, "OnError must behave like samlOnError (403), not leave samlsp's default in place")
}

// TestSAMLRegistry_Provider_WarnsOnInsecureSPBaseURLOnEveryBuild is a
// regression test for a real gap found in review: main.go's own
// insecure-sp_base_url warning only runs once, from the config
// snapshot at process startup, so a SAML source hot-added or
// hot-edited to an insecure sp_base_url later never re-triggers it.
// Warning here too — on every actual provider build, not just once —
// is what catches that case, since providers build lazily on first use
// rather than eagerly at startup.
func TestSAMLRegistry_Provider_WarnsOnInsecureSPBaseURLOnEveryBuild(t *testing.T) {
	t.Setenv("TEST_SAML_INSECURE_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)

	var buf bytes.Buffer
	r := NewSAMLRegistry(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(r.Close)

	src := testSAMLSource(idp)
	src.SessionSigningKeyEnv = "TEST_SAML_INSECURE_KEY"
	src.SPBaseURL = "http://proxy.example.com" // insecure, on purpose
	src.SPEntityID = "http://proxy.example.com/saml/metadata"

	_, err := r.Provider(src)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "not https")
	assert.Contains(t, buf.String(), "http://proxy.example.com")
}

// --- buildSAMLProvider (the real, non-faked newSAMLProviderFunc) ---

func testIDPMetadata(t *testing.T, idp *TestSAMLIDP) *saml.EntityDescriptor {
	t.Helper()
	entity, err := samlsp.ParseMetadata(idp.MetadataXML(t))
	require.NoError(t, err)
	return entity
}

func TestBuildSAMLProvider_WiresACSURLAndOmitsKey(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)

	mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
	require.NoError(t, err)

	assert.Nil(t, mw.ServiceProvider.Key, "no persistent SP keypair — see buildSAMLProvider's doc comment")
	assert.Nil(t, mw.ServiceProvider.Certificate)
	assert.Equal(t, src.SPEntityID, mw.ServiceProvider.EntityID)
	assert.Equal(t, "https://proxy.example.com/saml/acs", mw.ServiceProvider.AcsURL.String(),
		"samlsp.New hardcodes saml/acs relative to Options.URL; buildSAMLProvider must overwrite it with the configured acs_path")
}

func TestBuildSAMLProvider_SessionAndTrackerCodecsWired(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)

	mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
	require.NoError(t, err)

	session, ok := mw.Session.(samlsp.CookieSessionProvider)
	require.True(t, ok, "Session must be a CookieSessionProvider, not samlsp's default")
	assert.Equal(t, src.SessionCookie, session.Name)
	assert.Equal(t, src.SessionDuration, session.MaxAge)
	assert.True(t, session.HTTPOnly, "the session cookie carries a signed session JWT and must never be script-readable — "+
		"CookieSessionProvider's own zero value is HTTPOnly:false, unlike CookieRequestTracker which hardcodes HttpOnly:true internally")
	_, ok = session.Codec.(samlSessionCodec)
	assert.True(t, ok, "Session.Codec must be our own HS256 codec, not samlsp's asymmetric default")

	tracker, ok := mw.RequestTracker.(samlsp.CookieRequestTracker)
	require.True(t, ok, "RequestTracker must be a CookieRequestTracker, not samlsp's default")
	_, ok = tracker.Codec.(samlTrackedRequestCodec)
	assert.True(t, ok, "RequestTracker.Codec must be our own HS256 codec, not samlsp's asymmetric default")
}

func TestBuildSAMLProvider_SameSiteFollowsScheme(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)

	for _, tc := range []struct {
		name            string
		spBaseURL       string
		wantSecure      bool
		wantTrackerSame http.SameSite
		wantSessionSame http.SameSite
	}{
		{"https", "https://proxy.example.com", true, http.SameSiteNoneMode, http.SameSiteLaxMode},
		{"http", "http://127.0.0.1:8080", false, http.SameSiteLaxMode, http.SameSiteLaxMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := testSAMLSource(idp)
			src.SPBaseURL = tc.spBaseURL
			src.SPEntityID = tc.spBaseURL + "/saml/metadata"

			mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
			require.NoError(t, err)

			session := mw.Session.(samlsp.CookieSessionProvider)       //nolint:forcetypeassert // asserted by TestBuildSAMLProvider_SessionAndTrackerCodecsWired
			tracker := mw.RequestTracker.(samlsp.CookieRequestTracker) //nolint:forcetypeassert // asserted by TestBuildSAMLProvider_SessionAndTrackerCodecsWired

			assert.Equal(t, tc.wantSecure, session.Secure)
			assert.Equal(t, tc.wantSessionSame, session.SameSite)
			assert.Equal(t, tc.wantTrackerSame, tracker.SameSite,
				"the ACS cross-site POST tracker cookie must be SameSite=None over https (browsers only honor None on Secure cookies) — see buildSAMLProvider's doc comment for the bug this guards")
		})
	}
}

func TestBuildSAMLProvider_SessionSigningKeyEnv(t *testing.T) {
	idp := NewTestSAMLIDP(t)
	entity := testIDPMetadata(t, idp)

	t.Run("unset", func(t *testing.T) {
		src := testSAMLSource(idp)
		src.SessionSigningKeyEnv = "TEST_SAML_SESSION_KEY_UNSET_" + t.Name()
		_, err := buildSAMLProvider(src, entity)
		require.Error(t, err)
		assert.ErrorContains(t, err, "not set")
	})

	t.Run("too short", func(t *testing.T) {
		t.Setenv("TEST_SAML_SESSION_KEY_SHORT", "short")
		src := testSAMLSource(idp)
		src.SessionSigningKeyEnv = "TEST_SAML_SESSION_KEY_SHORT"
		_, err := buildSAMLProvider(src, entity)
		require.Error(t, err)
		assert.ErrorContains(t, err, "at least")
	})
}

func TestBuildSAMLProvider_SPKeyCertEnablesEncryption(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)

	priv, cert := newSAMLIDPKeypair(t, true) // fresh — must differ from idp's own keypair
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	t.Setenv("TEST_SAML_SP_KEY", keyPEM)
	src.SPKeyEnv = "TEST_SAML_SP_KEY"
	src.SPCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
	require.NoError(t, err)

	require.NotNil(t, mw.ServiceProvider.Key)
	require.NotNil(t, mw.ServiceProvider.Certificate)
	assert.Equal(t, cert.Raw, mw.ServiceProvider.Certificate.Raw)

	meta := mw.ServiceProvider.Metadata()
	require.Len(t, meta.SPSSODescriptors, 1)
	var hasEncryptionKey bool
	for _, kd := range meta.SPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "encryption" {
			hasEncryptionKey = true
		}
	}
	assert.True(t, hasEncryptionKey, "sp metadata must advertise an encryption key when sp_key_env/sp_cert are configured")
}

func TestBuildSAMLProvider_NoSPKeyCert_NoEncryptionKeyAdvertised(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	src := testSAMLSource(idp)

	mw, err := buildSAMLProvider(src, testIDPMetadata(t, idp))
	require.NoError(t, err)

	assert.Nil(t, mw.ServiceProvider.Key)
	assert.Nil(t, mw.ServiceProvider.Certificate)
	meta := mw.ServiceProvider.Metadata()
	require.Len(t, meta.SPSSODescriptors, 1)
	assert.Empty(t, meta.SPSSODescriptors[0].KeyDescriptors, "no sp keypair configured must mean no encryption key advertised")
}

func TestBuildSAMLProvider_SPKeyEnv_DefenseInDepth(t *testing.T) {
	t.Setenv("TEST_SAML_SESSION_KEY", validSAMLSessionKeyForTest)
	idp := NewTestSAMLIDP(t)
	entity := testIDPMetadata(t, idp)
	_, cert := newSAMLIDPKeypair(t, true)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	t.Run("env unset", func(t *testing.T) {
		src := testSAMLSource(idp)
		src.SPKeyEnv = "TEST_SAML_SP_KEY_UNSET_" + t.Name()
		src.SPCert = certPEM
		_, err := buildSAMLProvider(src, entity)
		require.Error(t, err)
		assert.ErrorContains(t, err, "sp_key_env")
	})

	t.Run("malformed pem", func(t *testing.T) {
		t.Setenv("TEST_SAML_SP_KEY_MALFORMED", "not a pem key")
		src := testSAMLSource(idp)
		src.SPKeyEnv = "TEST_SAML_SP_KEY_MALFORMED"
		src.SPCert = certPEM
		_, err := buildSAMLProvider(src, entity)
		require.Error(t, err)
		assert.ErrorContains(t, err, "sp_key_env")
	})
}

func TestValidateSAMLAudienceRestriction(t *testing.T) {
	const spEntityID = "https://proxy.example.com/saml/metadata"

	restriction := func(values ...string) *saml.Conditions {
		var ars []saml.AudienceRestriction
		for _, v := range values {
			ars = append(ars, saml.AudienceRestriction{Audience: saml.Audience{Value: v}})
		}
		return &saml.Conditions{AudienceRestrictions: ars}
	}

	tests := []struct {
		name       string
		conditions *saml.Conditions
		extra      []string
		wantErr    bool
	}{
		{"no conditions", nil, nil, false},
		{"no restrictions", &saml.Conditions{}, nil, false},
		{"matches sp entity id", restriction(spEntityID), nil, false},
		{"matches configured extra audience", restriction("https://other.example.com"), []string{"https://other.example.com"}, false},
		{"matches neither", restriction("https://unknown.example.com"), []string{"https://other.example.com"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertion := &saml.Assertion{Conditions: tc.conditions}
			err := validateSAMLAudienceRestriction(assertion, spEntityID, tc.extra)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
