package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

const (
	maxRegistrationBody = 16 << 10
	maxClientNameLen    = 100
	maxRedirectURILen   = 512
	maxRegisteredURIs   = 10
)

// clientData is what a dynamically registered client's ID carries. Nothing is
// stored: the ID is the sealed registration, so any replica opens it, and
// replacing every sealing key revokes all of them.
type clientData struct {
	URIs []string `json:"u"`
}

// registrationRequest is the part of RFC 7591 client metadata that matters
// here. Everything else a client sends is ignored.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

type registrationError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serveRegister is RFC 7591 client registration for public clients. It stores
// nothing and asks for no authentication; what keeps it safe is that a client
// only gets redirect URIs the operator allows (loopback, or an https URI
// listed in the configuration), and that it can never be confidential.
func (r *Registry) serveRegister(w http.ResponseWriter, req *http.Request, s *server) {
	cfg := r.live.Load()
	if cfg == nil || !cfg.OAuthEnabled() || !cfg.Inbound.OAuthServer.DynamicRegistration.Enabled {
		http.NotFound(w, req)
		return
	}
	dr := cfg.Inbound.OAuthServer.DynamicRegistration

	w.Header().Set("Access-Control-Allow-Origin", "*")
	switch req.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var in registrationRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxRegistrationBody))
	if err != nil || json.Unmarshal(body, &in) != nil {
		writeJSON(w, http.StatusBadRequest, registrationError{"invalid_client_metadata", "the body must be a JSON object of client metadata, at most 16 KiB"})
		return
	}
	bad := func(code, msg string) { writeJSON(w, http.StatusBadRequest, registrationError{code, msg}) }

	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > maxRegisteredURIs {
		bad("invalid_redirect_uri", "redirect_uris must list between 1 and 10 URIs")
		return
	}
	for _, u := range in.RedirectURIs {
		if len(u) > maxRedirectURILen || !dr.AllowsDynamicRedirect(u) {
			bad("invalid_redirect_uri", "redirect URI not allowed: it must be an http loopback URI or one the server permits")
			return
		}
	}
	if m := in.TokenEndpointAuthMethod; m != "" && m != "none" {
		bad("invalid_client_metadata", `token_endpoint_auth_method must be "none": only public clients with PKCE are supported`)
		return
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			bad("invalid_client_metadata", "grant_types may only be authorization_code and refresh_token")
			return
		}
	}
	if len(in.GrantTypes) > 0 && !slices.Contains(in.GrantTypes, "authorization_code") {
		bad("invalid_client_metadata", "grant_types must include authorization_code")
		return
	}
	for _, t := range in.ResponseTypes {
		if t != "code" {
			bad("invalid_client_metadata", `response_types may only be "code"`)
			return
		}
	}
	if len(in.ResponseTypes) > 0 && !slices.Contains(in.ResponseTypes, "code") {
		bad("invalid_client_metadata", `response_types must include "code"`)
		return
	}

	name := truncate(strings.ToValidUTF8(in.ClientName, ""), maxClientNameLen)
	now := time.Now()
	id, err := s.sealer.seal(kindClient, clientData{URIs: slices.Clone(in.RedirectURIs)})
	if err != nil {
		r.logger.Error("oauth client registration failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	r.logger.Info("oauth client registered", "name", name, "redirect_uris", in.RedirectURIs)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        now.Unix(),
		"client_name":                name,
		"redirect_uris":              in.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

// lookupClient finds a client by ID: a configured one, or a registered one
// whose ID opens. A registered client is checked against the current
// configuration every time: turning registration off ends it, and a redirect
// URI that is no longer permitted is dropped from it (it ends when none is left).
func (s *storage) lookupClient(id string) (*client, bool) {
	if c, ok := s.clients[id]; ok {
		return c, true
	}
	srv, _, err := s.settings()
	if err != nil || !srv.DynamicRegistration.Enabled {
		return nil, false
	}
	var d clientData
	if err := s.sealer.open(kindClient, id, &d); err != nil || len(d.URIs) == 0 {
		return nil, false
	}
	var allowed []string
	for _, u := range d.URIs {
		if srv.DynamicRegistration.AllowsDynamicRedirect(u) {
			allowed = append(allowed, u)
		}
	}
	if len(allowed) == 0 {
		return nil, false
	}
	return &client{cfg: config.OAuthClient{ID: id, RedirectURIs: allowed}, issuer: s.issuer}, true
}
