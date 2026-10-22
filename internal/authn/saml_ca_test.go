package authn

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// tlsMetadataSource serves idp's metadata over HTTPS with httptest's
// built-in certificate, which no system trust store knows, and returns
// a source that fetches it. The server's own certificate is the CA
// bundle that makes the fetch work.
func tlsMetadataSource(t *testing.T, idp *TestSAMLIDP) (config.SAMLSource, string) {
	t.Helper()
	body := idp.MetadataXML(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	src := testSAMLSource(idp)
	src.IDPMetadataURL = server.URL
	return src, string(pemOf(server.Certificate().Raw))
}

func TestSAMLRegistry_Provider_CACertTrustsAPrivateMetadataServer(t *testing.T) {
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, new(sync.Mutex), nil))
	idp := NewTestSAMLIDP(t)
	src, caPEM := tlsMetadataSource(t, idp)
	src.CACert = caPEM

	_, err := r.Provider(src)
	require.NoError(t, err)
	assert.Len(t, calls, 1)
}

func TestSAMLRegistry_Provider_WithoutCACertAPrivateMetadataServerIsRejected(t *testing.T) {
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, new(sync.Mutex), nil))
	idp := NewTestSAMLIDP(t)
	src, _ := tlsMetadataSource(t, idp)

	_, err := r.Provider(src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
	assert.Empty(t, calls)
}

func TestSAMLRegistry_Provider_CACertReplacesTheSystemRoots(t *testing.T) {
	var calls []samlProviderCall
	r := newTestSAMLRegistry(t, newFakeSAMLProvider(&calls, new(sync.Mutex), nil))
	idp := NewTestSAMLIDP(t)
	src, _ := tlsMetadataSource(t, idp)
	src.CACert = newTestCAPEM(t) // some other CA: the server's certificate is not signed by it

	_, err := r.Provider(src)
	require.Error(t, err)
	assert.Empty(t, calls)
}

func TestSAMLFingerprint_ChangesWithCACert(t *testing.T) {
	idp := NewTestSAMLIDP(t)
	a := testSAMLSource(idp)
	b := a
	b.CACert = newTestCAPEM(t)
	assert.NotEqual(t, samlFingerprint(a), samlFingerprint(b))
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
