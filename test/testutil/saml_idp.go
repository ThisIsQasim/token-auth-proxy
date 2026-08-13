package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// samlIDPMetadataPath and samlIDPSSOPath are fixed, arbitrary paths —
// known before the httptest server picks a port, so they can be
// registered on the mux first and turned into full URLs (using the
// port Start() assigns) afterward. Mirrors TestIDP's identical
// two-phase approach for /jwks.json and /.well-known/openid-configuration.
const (
	samlIDPMetadataPath = "/saml/metadata"
	samlIDPSSOPath      = "/saml/sso"
)

// RSA key generation is real crypto work — cached once per process so
// every test using the default (non-rotated) TestSAMLIDP keypair
// doesn't pay for it separately. Rotate always generates a genuinely
// fresh keypair, deliberately not using this, since a rotation test
// needs the "before" and "after" keys/certs to actually differ. Same
// pattern, same sharp edge, as idp.go's sharedRSAKey: two independent
// NewTestSAMLIDP(tb) calls (neither Rotated) share one underlying
// keypair.
var sharedSAMLIDPKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// newSAMLIDPKeypair returns an RSA keypair and a self-signed
// certificate binding it — the shared cached keypair, or a genuinely
// fresh one when fresh is true.
func newSAMLIDPKeypair(tb testing.TB, fresh bool) (*rsa.PrivateKey, *x509.Certificate) {
	tb.Helper()

	var (
		priv *rsa.PrivateKey
		err  error
	)
	if fresh {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		priv, err = sharedSAMLIDPKey()
	}
	if err != nil {
		tb.Fatalf("generate RSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		tb.Fatalf("generate certificate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-saml-idp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("create self-signed certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse self-signed certificate: %v", err)
	}
	return priv, cert
}

func mustParseSAMLURL(tb testing.TB, s string) url.URL {
	tb.Helper()
	u, err := url.Parse(s)
	if err != nil {
		tb.Fatalf("parse url %q: %v", s, err)
	}
	return *u
}

// TestSAMLIDP is a stand-in SAML identity provider: an httptest server
// serving IdP metadata and an SSO endpoint via the real
// saml.IdentityProvider (so requests are validated and assertions are
// really XML-DSig-signed, not hand-rolled), auto-authenticating
// whichever single user was last set via SetUser rather than presenting
// a login form. It's the non-test-file mirror of internal/authn's
// identical fixture — kept separate rather than shared, since _test.go
// files can't be imported across a module's package boundary, matching
// idp.go's existing rationale.
type TestSAMLIDP struct {
	Server      *httptest.Server
	Issuer      string // saml.IdentityProvider.Metadata().EntityID
	MetadataURL string
	SSOURL      string

	idp *saml.IdentityProvider

	mu      sync.Mutex
	sps     map[string]*saml.EntityDescriptor // keyed by SP entityID
	user    *saml.Session
	userSeq int
}

// NewTestSAMLIDP starts a TestSAMLIDP and registers tb.Cleanup to shut
// it down.
func NewTestSAMLIDP(tb testing.TB) *TestSAMLIDP {
	tb.Helper()

	fixture := &TestSAMLIDP{sps: make(map[string]*saml.EntityDescriptor)}
	priv, cert := newSAMLIDPKeypair(tb, false)

	real := &saml.IdentityProvider{
		Key:                     priv,
		Certificate:             cert,
		Logger:                  log.New(os.Stderr, "[test-saml-idp] ", log.LstdFlags),
		ServiceProviderProvider: fixture,
		SessionProvider:         fixture,
	}
	fixture.idp = real

	mux := http.NewServeMux()
	mux.HandleFunc(samlIDPMetadataPath, real.ServeMetadata)
	mux.HandleFunc(samlIDPSSOPath, real.ServeSSO)

	// Unstarted-then-Start avoids a data race between setting
	// real.MetadataURL/SSOURL below and the server's handler
	// goroutines reading them via req.IDP — nothing can reach the
	// handlers until Start runs.
	fixture.Server = httptest.NewUnstartedServer(mux)
	tb.Cleanup(fixture.Server.Close)
	fixture.Server.Start()

	real.MetadataURL = mustParseSAMLURL(tb, fixture.Server.URL+samlIDPMetadataPath)
	real.SSOURL = mustParseSAMLURL(tb, fixture.Server.URL+samlIDPSSOPath)

	fixture.Issuer = real.MetadataURL.String()
	fixture.MetadataURL = real.MetadataURL.String()
	fixture.SSOURL = real.SSOURL.String()

	return fixture
}

// RegisterSP adds (or replaces) the SP metadata this IdP will recognize
// requests from: entityID must match the AuthnRequest's Issuer (i.e.
// SAMLSource.SPEntityID), and acsURL must exactly match the URL the SP
// puts in its AuthnRequest's AssertionConsumerServiceURL — getACSEndpoint
// matches by exact Location, not by prefix or path. Deliberately
// registers no KeyDescriptors, matching a real keyless SP (see
// buildSAMLProvider's doc comment): getSPEncryptionCert then finds
// nothing to encrypt to, so assertions come back signed but plaintext.
func (fixture *TestSAMLIDP) RegisterSP(entityID, acsURL string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.sps[entityID] = &saml.EntityDescriptor{
		EntityID: entityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				},
			},
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding:  saml.HTTPPostBinding,
				Location: acsURL,
				Index:    0,
			}},
		}},
	}
}

// RegisterSPEncryptionCert adds an encryption KeyDescriptor (advertising
// cert) to the SP metadata previously registered via RegisterSP for
// entityID. MakeAssertionEl's getSPEncryptionCert lookup then finds it
// and automatically encrypts assertions to it (RSA-OAEP + AES128CBC),
// exactly mirroring how a real IdP would once it fetches an SP's real
// metadata advertising an encryption key — this fixture never fetches
// anything, so the test has to hand it the cert directly. RegisterSP
// must be called first for entityID.
func (fixture *TestSAMLIDP) RegisterSPEncryptionCert(entityID string, cert *x509.Certificate) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	sp, ok := fixture.sps[entityID]
	if !ok {
		panic("test-saml-idp: RegisterSPEncryptionCert called before RegisterSP for " + entityID)
	}
	sp.SPSSODescriptors[0].KeyDescriptors = append(sp.SPSSODescriptors[0].KeyDescriptors, saml.KeyDescriptor{
		Use: "encryption",
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}},
			},
		},
	})
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (fixture *TestSAMLIDP) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	sp, ok := fixture.sps[serviceProviderID]
	if !ok {
		// The library checks this exact sentinel by equality (== os.ErrNotExist),
		// not errors.Is, so it must be returned unwrapped.
		return nil, os.ErrNotExist
	}
	return sp, nil
}

// SetUser sets the single user this IdP will authenticate as, for every
// SSO request, until the next SetUser call — there's no login form:
// GetSession always logs in as whoever was set here. attrs becomes the
// assertion's CustomAttributes, keyed by FriendlyName, matching how a
// real IdP's admin-configured attribute release would show up.
func (fixture *TestSAMLIDP) SetUser(nameID string, attrs map[string][]string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()

	fixture.userSeq++
	var custom []saml.Attribute
	for name, values := range attrs {
		var avs []saml.AttributeValue
		for _, v := range values {
			avs = append(avs, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		custom = append(custom, saml.Attribute{FriendlyName: name, Values: avs})
	}

	now := time.Now()
	fixture.user = &saml.Session{
		ID:               "test-session-id",
		CreateTime:       now,
		ExpireTime:       now.Add(time.Hour),
		Index:            fmt.Sprintf("test-session-index-%d", fixture.userSeq),
		NameID:           nameID,
		CustomAttributes: custom,
	}
}

// GetSession implements saml.SessionProvider.
func (fixture *TestSAMLIDP) GetSession(w http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	fixture.mu.Lock()
	user := fixture.user
	fixture.mu.Unlock()

	if user == nil {
		// Per the SessionProvider contract: no session means we must
		// complete the response ourselves.
		http.Error(w, "test-saml-idp: no user configured; call SetUser before driving a login", http.StatusForbidden)
		return nil
	}
	session := *user // copy: callers must not be able to mutate the fixture's state through the returned pointer
	return &session
}

// Rotate swaps in a genuinely fresh RSA keypair and self-signed
// certificate, for testing that a metadata consumer picks up a real key
// change rather than caching the original certificate forever. Not
// safe to call concurrently with an in-flight SSO request or metadata
// fetch: saml.IdentityProvider's Key/Certificate fields have no
// locking of their own (unlike TestIDP.Rotate, which is safe only
// because its own handlers re-read the shared keypair under the
// fixture's mutex on every request — the underlying library type here
// doesn't give us that seam), so callers must Rotate between requests,
// not during them.
func (fixture *TestSAMLIDP) Rotate(tb testing.TB) {
	tb.Helper()
	priv, cert := newSAMLIDPKeypair(tb, true)
	fixture.idp.Key = priv
	fixture.idp.Certificate = cert
}

// GenerateSPKeyCertPEM returns a fresh RSA keypair and self-signed
// certificate, PEM-encoded — usable as an SP's sp_key_env value
// (PKCS#1) and sp_cert field. Exported for integration tests, which
// need real PEM text to put in a real config file and env var, not
// just the parsed *rsa.PrivateKey/*x509.Certificate values
// newSAMLIDPKeypair itself returns.
func GenerateSPKeyCertPEM(tb testing.TB) (cert *x509.Certificate, keyPEM, certPEM string) {
	tb.Helper()
	priv, cert := newSAMLIDPKeypair(tb, true) // fresh — must differ from whatever IdP keypair it's paired with
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	return cert, keyPEM, certPEM
}

// MetadataXML returns the IdP's current metadata document, serialized
// exactly as the metadata endpoint would return it.
func (fixture *TestSAMLIDP) MetadataXML(tb testing.TB) []byte {
	tb.Helper()
	data, err := xml.MarshalIndent(fixture.idp.Metadata(), "", "  ")
	if err != nil {
		tb.Fatalf("marshal idp metadata: %v", err)
	}
	return data
}
