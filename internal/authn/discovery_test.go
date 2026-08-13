package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchJWKSURI_HappyPath(t *testing.T) {
	idp := NewTestIDP(t)

	uri, err := fetchJWKSURI(t.Context(), http.DefaultClient, idp.DiscoveryURL, idp.Issuer)
	require.NoError(t, err)
	assert.Equal(t, idp.JWKSURL, uri)
	assert.Equal(t, 1, idp.DiscoveryHits())

	// A second fetch hits the endpoint again — fetchJWKSURI itself does
	// no caching, that's the Registry's job (see jwks_test.go).
	_, err = fetchJWKSURI(t.Context(), http.DefaultClient, idp.DiscoveryURL, idp.Issuer)
	require.NoError(t, err)
	assert.Equal(t, 2, idp.DiscoveryHits())
}

func TestFetchJWKSURI_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchJWKSURI(t.Context(), http.DefaultClient, srv.URL, "https://issuer.example.com")
	require.Error(t, err)
}

func TestFetchJWKSURI_NonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := fetchJWKSURI(t.Context(), http.DefaultClient, srv.URL, "https://issuer.example.com")
	require.Error(t, err)
}

func TestFetchJWKSURI_MissingJWKSURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://issuer.example.com"})
	}))
	defer srv.Close()

	_, err := fetchJWKSURI(t.Context(), http.DefaultClient, srv.URL, "https://issuer.example.com")
	require.Error(t, err)
}

func TestFetchJWKSURI_InvalidJWKSURI(t *testing.T) {
	for _, uri := range []string{"not-a-url", "ftp://issuer.example.com/jwks.json", "/relative/path"} {
		t.Run(uri, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":   "https://issuer.example.com",
					"jwks_uri": uri,
				})
			}))
			defer srv.Close()

			_, err := fetchJWKSURI(t.Context(), http.DefaultClient, srv.URL, "https://issuer.example.com")
			require.Error(t, err)
		})
	}
}

func TestFetchJWKSURI_IssuerMismatchRejected(t *testing.T) {
	idp := NewTestIDP(t, WithIssuer("https://actual-issuer.example.com"))

	_, err := fetchJWKSURI(t.Context(), http.DefaultClient, idp.DiscoveryURL, "https://configured-issuer.example.com")
	require.Error(t, err)
	assert.ErrorContains(t, err, "issuer")
}
