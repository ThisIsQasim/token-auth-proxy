package authn

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSSOURL = "https://idp.example.com/sso"

// entityDescriptor builds a minimal, structurally valid IdP
// EntityDescriptor for entityID, with a signing KeyDescriptor and one
// SingleSignOnService — the shape validateIDPMetadataShape requires.
// The certificate value is a dummy string: these tests only exercise
// fetchIDPMetadata/validateIDPMetadataShape's structural checks, never
// real signature verification (that's saml_middleware_test.go's job,
// against the real TestSAMLIDP fixture).
func entityDescriptor(entityID string) saml.EntityDescriptor {
	return saml.EntityDescriptor{
		EntityID: entityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					KeyDescriptors: []saml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: saml.KeyInfo{
							X509Data: saml.X509Data{
								X509Certificates: []saml.X509Certificate{{Data: "dummy-cert-data"}},
							},
						},
					}},
				},
			},
			SingleSignOnServices: []saml.Endpoint{{
				Binding:  saml.HTTPRedirectBinding,
				Location: testSSOURL,
			}},
		}},
	}
}

func marshalMetadata(tb testing.TB, entity saml.EntityDescriptor) []byte {
	tb.Helper()
	data, err := xml.Marshal(entity)
	require.NoError(tb, err)
	return data
}

func metadataServer(tb testing.TB, body []byte, status int) *httptest.Server {
	tb.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	tb.Cleanup(srv.Close)
	return srv
}

func TestFetchIDPMetadata_HappyPath(t *testing.T) {
	entity := entityDescriptor("https://idp.example.com/metadata")
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	got, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/metadata", got.EntityID)
	require.Len(t, got.IDPSSODescriptors, 1)
	require.Len(t, got.IDPSSODescriptors[0].SingleSignOnServices, 1)
	assert.Equal(t, "https://idp.example.com/sso", got.IDPSSODescriptors[0].SingleSignOnServices[0].Location)
}

func TestFetchIDPMetadata_IssuerMismatch(t *testing.T) {
	entity := entityDescriptor("https://actual-idp.example.com/metadata")
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://configured-issuer.example.com/metadata")
	require.Error(t, err)
	assert.ErrorContains(t, err, "entityID")
}

func TestFetchIDPMetadata_NonOKStatus(t *testing.T) {
	srv := metadataServer(t, []byte("nope"), http.StatusInternalServerError)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
}

func TestFetchIDPMetadata_MalformedXML(t *testing.T) {
	srv := metadataServer(t, []byte("not xml at all"), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
}

func TestFetchIDPMetadata_EntitiesDescriptorWrapper(t *testing.T) {
	entity := entityDescriptor("https://idp.example.com/metadata")

	// samlsp.ParseMetadata handles an <EntitiesDescriptor> wrapper around
	// one or more <EntityDescriptor> elements — build one by hand, since
	// saml.EntitiesDescriptor's own XML marshaling isn't exercised
	// elsewhere and hand-wrapping is simplest here.
	inner := marshalMetadata(t, entity)
	wrapped := fmt.Sprintf(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">%s</EntitiesDescriptor>`, inner)
	srv := metadataServer(t, []byte(wrapped), http.StatusOK)

	got, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/metadata", got.EntityID)
}

func TestFetchIDPMetadata_NoIDPSSODescriptor(t *testing.T) {
	entity := saml.EntityDescriptor{EntityID: "https://idp.example.com/metadata"}
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
	assert.ErrorContains(t, err, "IDPSSODescriptor")
}

func TestFetchIDPMetadata_NoSigningKey(t *testing.T) {
	entity := entityDescriptor("https://idp.example.com/metadata")
	entity.IDPSSODescriptors[0].KeyDescriptors = nil
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
	assert.ErrorContains(t, err, "signing")
}

func TestFetchIDPMetadata_EncryptionOnlyKeyDoesNotCount(t *testing.T) {
	entity := entityDescriptor("https://idp.example.com/metadata")
	entity.IDPSSODescriptors[0].KeyDescriptors[0].Use = "encryption"
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
	assert.ErrorContains(t, err, "signing")
}

func TestFetchIDPMetadata_NoSSOService(t *testing.T) {
	entity := entityDescriptor("https://idp.example.com/metadata")
	entity.IDPSSODescriptors[0].SingleSignOnServices = nil
	srv := metadataServer(t, marshalMetadata(t, entity), http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err)
	assert.ErrorContains(t, err, "SingleSignOnService")
}

func TestFetchIDPMetadata_OversizeBodyCapped(t *testing.T) {
	// A body larger than maxIDPMetadataBytes must not be read in full —
	// it should fail (as truncated/malformed XML) rather than exhaust
	// memory. A valid entity padded with an oversize XML comment proves
	// the cap applies to the read itself, not just to obviously-bogus input.
	entity := entityDescriptor("https://idp.example.com/metadata")
	padding := strings.Repeat("x", maxIDPMetadataBytes+1)
	body := append(marshalMetadata(t, entity), []byte("<!--"+padding+"-->")...)
	srv := metadataServer(t, body, http.StatusOK)

	_, err := fetchIDPMetadata(t.Context(), http.DefaultClient, srv.URL, "https://idp.example.com/metadata")
	require.Error(t, err, "a body larger than maxIDPMetadataBytes must not parse successfully")
}
