package oauth

import (
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// pendingTTL is how long a person has to finish logging in at the identity
// provider (including any MFA step) after being sent there.
const pendingTTL = 10 * time.Minute

// reqData is the sealed content of a login request ID. The same payload is
// sealed as kindPending when the request is made and again as kindDone, with
// the identity filled in, once the person has logged in. Short JSON names
// keep the URLs it travels in short.
type reqData struct {
	ClientID    string   `json:"c"`
	RedirectURI string   `json:"r"`
	State       string   `json:"s,omitempty"`
	Nonce       string   `json:"n,omitempty"`
	Scopes      []string `json:"sc,omitempty"`
	Challenge   string   `json:"ch"`
	Method      string   `json:"m"`

	// Set by the login, never by the client.
	Sub      string   `json:"u,omitempty"`
	Email    string   `json:"e,omitempty"`
	Groups   []string `json:"g,omitempty"`
	Mode     string   `json:"am,omitempty"`
	AuthTime int64    `json:"at,omitempty"`

	Exp int64 `json:"x"`
}

// authReq adapts a sealed login request to op.AuthRequest. Its ID is the
// sealed text itself, which is how the library finds it again with no table.
type authReq struct {
	d        reqData
	id       string
	done     bool
	audience string
}

var _ op.AuthRequest = (*authReq)(nil)

func (a *authReq) GetID() string          { return a.id }
func (a *authReq) GetACR() string         { return "" }
func (a *authReq) GetAudience() []string  { return []string{a.audience} }
func (a *authReq) GetAuthTime() time.Time { return time.Unix(a.d.AuthTime, 0) }
func (a *authReq) GetClientID() string    { return a.d.ClientID }
func (a *authReq) GetCodeChallenge() *oidc.CodeChallenge {
	return &oidc.CodeChallenge{Challenge: a.d.Challenge, Method: oidc.CodeChallengeMethod(a.d.Method)}
}
func (a *authReq) GetNonce() string                   { return a.d.Nonce }
func (a *authReq) GetRedirectURI() string             { return a.d.RedirectURI }
func (a *authReq) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }
func (a *authReq) GetResponseMode() oidc.ResponseMode { return "" }
func (a *authReq) GetScopes() []string                { return a.d.Scopes }
func (a *authReq) GetState() string                   { return a.d.State }
func (a *authReq) GetSubject() string                 { return a.d.Sub }
func (a *authReq) Done() bool                         { return a.done }

func (a *authReq) GetAMR() []string {
	if a.d.Mode == "" {
		return nil
	}
	return []string{a.d.Mode}
}

// refreshData is the sealed content of a refresh token.
type refreshData struct {
	Sub      string   `json:"u"`
	Email    string   `json:"e,omitempty"`
	Groups   []string `json:"g,omitempty"`
	Mode     string   `json:"am,omitempty"`
	ClientID string   `json:"c"`
	Scopes   []string `json:"sc,omitempty"`
	AuthTime int64    `json:"at"`

	// Exp is fixed at the login: refreshing never extends it.
	Exp int64 `json:"x"`
}

// refreshReq adapts a refresh token to op.RefreshTokenRequest.
type refreshReq struct {
	d        refreshData
	audience string
}

var _ op.RefreshTokenRequest = (*refreshReq)(nil)

func (r *refreshReq) GetAudience() []string       { return []string{r.audience} }
func (r *refreshReq) GetAuthTime() time.Time      { return time.Unix(r.d.AuthTime, 0) }
func (r *refreshReq) GetClientID() string         { return r.d.ClientID }
func (r *refreshReq) GetScopes() []string         { return r.d.Scopes }
func (r *refreshReq) GetSubject() string          { return r.d.Sub }
func (r *refreshReq) SetCurrentScopes(s []string) { r.d.Scopes = s }
func (r *refreshReq) GetAMR() []string {
	if r.d.Mode == "" {
		return nil
	}
	return []string{r.d.Mode}
}

// client is a registered public client, adapted to op.Client. Every client
// is a native/public one: no secret, PKCE required, JWT access tokens.
type client struct {
	cfg    config.OAuthClient
	issuer string
}

var _ op.Client = (*client)(nil)

// allowsRedirect reports whether raw is a redirect URI the client registered.
// It is stricter than the library, which for a native client compares only
// the path and query of a loopback redirect: here the scheme and host must
// match too, so a client registered for http://localhost/callback cannot be
// sent to https://localhost/callback or http://127.0.0.1/callback. Only the
// port of a registered http loopback URI is free, as RFC 8252 asks.
func (c *client) allowsRedirect(raw string) bool {
	got, err := url.Parse(raw)
	if err != nil || got.Fragment != "" || got.User != nil {
		return false
	}
	for _, reg := range c.cfg.RedirectURIs {
		if reg == raw {
			return true
		}
		want, err := url.Parse(reg)
		if err != nil || want.Scheme != "http" || !config.IsLoopbackHost(want.Hostname()) {
			continue
		}
		if got.Scheme == want.Scheme && got.Hostname() == want.Hostname() && got.Path == want.Path && got.RawQuery == want.RawQuery {
			return true
		}
	}
	return false
}

func (c *client) GetID() string                    { return c.cfg.ID }
func (c *client) RedirectURIs() []string           { return c.cfg.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return nil }
func (c *client) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeNative
}
func (c *client) AuthMethod() oidc.AuthMethod { return oidc.AuthMethodNone }
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *client) LoginURL(id string) string {
	return c.issuer + "/login?id=" + url.QueryEscape(id)
}
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *client) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (c *client) DevMode() bool                       { return false }

// The name is the library interface's, spelling included.
//
//nolint:staticcheck // ST1003: required by op.Client
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) IsScopeAllowed(scope string) bool     { return scope == "groups" }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }
