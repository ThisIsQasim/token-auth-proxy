package authn

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// maxIDPMetadataBytes caps how much of a SAML IdP metadata document this
// proxy will read, mirroring discovery.go's maxDiscoveryBodyBytes.
// samlsp.FetchMetadata does an unbounded io.ReadAll, which is why this
// package fetches the document itself and only borrows
// samlsp.ParseMetadata for the XML parsing.
const maxIDPMetadataBytes = 1 << 20 // 1 MiB

// fetchIDPMetadata fetches and parses the SAML IdP metadata document at
// metadataURL using client, after checking:
//   - the response is 200 and parses as SAML metadata — samlsp.ParseMetadata
//     handles both a bare <EntityDescriptor> and an <EntitiesDescriptor>
//     wrapper (picking the first entry with an IDPSSODescriptor);
//   - the document's entityID equals wantIssuer exactly — the SAML
//     analog of fetchJWKSURI's issuer cross-check, and the one thing
//     that stops a hijacked/misdirected metadata URL from silently
//     re-pointing the SP at a different IdP;
//   - it's structurally usable: at least one IDPSSODescriptor, at least
//     one signing-capable KeyDescriptor, at least one SingleSignOnService
//     location — so a metadata document that parses fine but can't
//     actually be used fails here, once, loudly, instead of deep inside
//     a redirect or an assertion-verification call later.
func fetchIDPMetadata(ctx context.Context, client *http.Client, metadataURL, wantIssuer string) (*saml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build metadata request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G107 -- metadataURL comes from validated operator config, not request input
	if err != nil {
		return nil, fmt.Errorf("fetch idp metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("idp metadata: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIDPMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("read idp metadata: %w", err)
	}

	entity, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, fmt.Errorf("parse idp metadata: %w", err)
	}

	if entity.EntityID != wantIssuer {
		return nil, fmt.Errorf("idp metadata entityID %q does not match configured issuer %q", entity.EntityID, wantIssuer)
	}

	if err := validateIDPMetadataShape(entity); err != nil {
		return nil, fmt.Errorf("idp metadata: %w", err)
	}

	return entity, nil
}

// validateIDPMetadataShape checks that entity actually describes a
// usable SAML IdP: at least one IDPSSODescriptor, at least one
// signing-capable key, at least one SSO redirect location. Nothing here
// is inferred as a trust parameter (which algorithm, which endpoint to
// prefer) — that stays samlsp's job at request time; this only rejects
// documents too structurally incomplete to ever work.
func validateIDPMetadataShape(entity *saml.EntityDescriptor) error {
	if len(entity.IDPSSODescriptors) == 0 {
		return fmt.Errorf("no IDPSSODescriptor present")
	}

	var hasSigningKey, hasSSOService bool
	for _, idp := range entity.IDPSSODescriptors {
		for _, kd := range idp.KeyDescriptors {
			// An empty Use means the key is valid for both signing and
			// encryption per the SAML metadata spec's default.
			if kd.Use == "" || kd.Use == "signing" {
				hasSigningKey = true
			}
		}
		if len(idp.SingleSignOnServices) > 0 {
			hasSSOService = true
		}
	}
	if !hasSigningKey {
		return fmt.Errorf("no signing KeyDescriptor present")
	}
	if !hasSSOService {
		return fmt.Errorf("no SingleSignOnService present")
	}
	return nil
}
