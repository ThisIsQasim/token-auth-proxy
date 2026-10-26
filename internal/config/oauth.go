package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// OAuthPathPrefix is the route family of the OAuth authorization server
	// (inbound.oauth_server). It is handled by the proxy itself and never
	// reaches the backend.
	OAuthPathPrefix = "/_tap/oauth"

	// OAuthSourceName names the JWT source the proxy derives for the tokens
	// it issues itself. ACL rules reference it as `mode: jwt, source: ...`;
	// no configured inbound.auth.jwt source may use it.
	OAuthSourceName = "tap-oauth"

	defaultAccessTokenTTL          = 15 * time.Minute
	defaultCodeTTL                 = 60 * time.Second
	defaultRefreshAbsoluteLifetime = 24 * time.Hour

	minAccessTokenTTL = time.Minute
	maxAccessTokenTTL = time.Hour
	minCodeTTL        = 5 * time.Second
	maxCodeTTL        = 5 * time.Minute
	maxRefreshLife    = 365 * 24 * time.Hour

	// sealingKeyLen is the AES-256 key size the sealing keys decode to.
	sealingKeyLen = 32

	defaultClaimSubject = "sub"
	defaultClaimEmail   = "email"
	defaultClaimGroups  = "groups"
)

// TokenConfig is outbound.token: the credential the backend receives when
// inbound.oauth_server is enabled. The proxy signs these JWTs itself; the
// backend verifies them against the proxy's published JWKS.
type TokenConfig struct {
	// SigningKeys are ES256 (P-256) private keys in PEM. The first signs;
	// every key is published in the JWKS and verifies, so a rotated-out key
	// can stay listed until the tokens it signed have expired.
	SigningKeys []SigningKey `yaml:"signing_keys"`

	// AccessTokenTTL is the lifetime of an access token. Defaults to 15m.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl,omitempty"`

	// Audience is the aud claim of issued tokens, which the proxy and the
	// backend check. Defaults to inbound.oauth_server.mcp_url.
	Audience string `yaml:"audience,omitempty"`

	// Claims names the claim (JWT login) or attribute (SAML) of the user's
	// login that supplies each value in the issued token. The values are
	// copied as they are; there are no transforms.
	Claims TokenClaims `yaml:"claims,omitempty"`

	keys []ParsedSigningKey
}

// SigningKey is one entry of TokenConfig.SigningKeys.
type SigningKey struct {
	KID        string `yaml:"kid"`
	PrivateKey string `yaml:"private_key"` // PEM; write it as ${file:PATH}
}

// TokenClaims maps login claims onto the claims of an issued token.
type TokenClaims struct {
	Subject string `yaml:"subject,omitempty"` // defaults to "sub"
	Email   string `yaml:"email,omitempty"`   // defaults to "email"
	Groups  string `yaml:"groups,omitempty"`  // defaults to "groups"
}

// ParsedSigningKey is a validated TokenConfig signing key.
type ParsedSigningKey struct {
	KID string
	Key *ecdsa.PrivateKey
}

// Keys returns the parsed signing keys in configuration order. Empty until
// Validate has succeeded.
func (t *TokenConfig) Keys() []ParsedSigningKey { return t.keys }

func (t *TokenConfig) applyDefaults(mcpURL string) {
	if t.AccessTokenTTL == 0 {
		t.AccessTokenTTL = defaultAccessTokenTTL
	}
	if t.Audience == "" {
		t.Audience = mcpURL
	}
	if t.Claims.Subject == "" {
		t.Claims.Subject = defaultClaimSubject
	}
	if t.Claims.Email == "" {
		t.Claims.Email = defaultClaimEmail
	}
	if t.Claims.Groups == "" {
		t.Claims.Groups = defaultClaimGroups
	}
}

func (t *TokenConfig) validate() error {
	if len(t.SigningKeys) == 0 {
		return fmt.Errorf("signing_keys requires at least one key")
	}
	kids := make(map[string]bool, len(t.SigningKeys))
	keys := make([]ParsedSigningKey, 0, len(t.SigningKeys))
	for i, k := range t.SigningKeys {
		if k.KID == "" {
			return fmt.Errorf("signing_keys[%d].kid is required", i)
		}
		if err := markUnique(kids, "signing_keys kid", k.KID); err != nil {
			return fmt.Errorf("signing_keys[%d]: %w", i, err)
		}
		key, err := parseECPrivateKey(k.PrivateKey)
		if err != nil {
			return fmt.Errorf("signing_keys[%d].private_key: %w", i, err)
		}
		keys = append(keys, ParsedSigningKey{KID: k.KID, Key: key})
	}
	if t.AccessTokenTTL < minAccessTokenTTL || t.AccessTokenTTL > maxAccessTokenTTL {
		return fmt.Errorf("access_token_ttl %s must be between %s and %s", t.AccessTokenTTL, minAccessTokenTTL, maxAccessTokenTTL)
	}
	if _, err := parseAbsoluteHTTPURL("audience", t.Audience); err != nil {
		return err
	}
	for name, v := range map[string]string{"claims.subject": t.Claims.Subject, "claims.email": t.Claims.Email, "claims.groups": t.Claims.Groups} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
	}
	t.keys = keys
	return nil
}

// parseECPrivateKey reads a PEM P-256 private key, in SEC1 or PKCS#8 form.
func parseECPrivateKey(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("not PEM encoded")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid EC private key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS#8 private key: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("must be an EC key, got %T", k)
		}
		key = ec
	default:
		return nil, fmt.Errorf("PEM type %q must be EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("must be a P-256 key (ES256)")
	}
	return key, nil
}

// OAuthServerConfig is inbound.oauth_server: the OAuth authorization server
// MCP clients log in to. Its tokens are described by outbound.token, which
// must be configured with it.
type OAuthServerConfig struct {
	// Disabled takes the server out of rotation without deleting its
	// configuration, like the same field on a source.
	Disabled bool `yaml:"disabled,omitempty"`

	// SPBaseURL is the proxy's own origin as the browser sees it. The issuer
	// is SPBaseURL + OAuthPathPrefix.
	SPBaseURL string `yaml:"sp_base_url"`

	// MCPURL is the public URL of the protected MCP endpoint. It is the
	// resource in the protected-resource metadata and the default audience.
	// It must share SPBaseURL's origin.
	MCPURL string `yaml:"mcp_url"`

	// CodeTTL is how long an authorization code, and the login result behind
	// it, is valid. Defaults to 60s.
	CodeTTL time.Duration `yaml:"code_ttl,omitempty"`

	// RefreshAbsoluteLifetime is how long after the login a refresh token
	// can renew the session. It is never extended by use. Defaults to 24h.
	RefreshAbsoluteLifetime time.Duration `yaml:"refresh_absolute_lifetime,omitempty"`

	// SealingKeys are base64 encoded 32-byte keys that seal login requests,
	// authorization codes and refresh tokens. The first seals; every key
	// opens, so a rotated-out key can stay listed until what it sealed has
	// expired. Write each as ${file:PATH}.
	SealingKeys []string `yaml:"sealing_keys"`

	// Clients are the public (PKCE-only, no secret) clients allowed to log in.
	Clients []OAuthClient `yaml:"clients"`

	// Denylist cuts off people immediately: a listed subject gets no new
	// login, no refresh and no access.
	Denylist OAuthDenylist `yaml:"denylist,omitempty"`

	sealing [][]byte
}

// OAuthClient is one registered client.
type OAuthClient struct {
	ID string `yaml:"id"`
	// RedirectURIs are exact https URLs, or http loopback URLs (localhost,
	// 127.0.0.1, [::1]) which match on any port, as RFC 8252 asks of native
	// apps.
	RedirectURIs []string `yaml:"redirect_uris"`
}

// OAuthDenylist lists subjects (the sub of the login) that are refused.
type OAuthDenylist struct {
	Subjects []string `yaml:"subjects,omitempty"`
}

// Contains reports whether sub is denylisted.
func (d OAuthDenylist) Contains(sub string) bool { return slices.Contains(d.Subjects, sub) }

// SealingKeyBytes returns the decoded sealing keys in configuration order.
// Empty until Validate has succeeded.
func (o *OAuthServerConfig) SealingKeyBytes() [][]byte { return o.sealing }

// Issuer is the issuer identifier of the authorization server.
func (o *OAuthServerConfig) Issuer() string {
	return strings.TrimRight(o.SPBaseURL, "/") + OAuthPathPrefix
}

// ProtectedResourceMetadataURL is where the RFC 9728 document is served.
func (o *OAuthServerConfig) ProtectedResourceMetadataURL() string {
	return o.Issuer() + "/protected-resource"
}

func (o *OAuthServerConfig) applyDefaults() {
	if o.CodeTTL == 0 {
		o.CodeTTL = defaultCodeTTL
	}
	if o.RefreshAbsoluteLifetime == 0 {
		o.RefreshAbsoluteLifetime = defaultRefreshAbsoluteLifetime
	}
}

func (o *OAuthServerConfig) validate() error {
	if o.SPBaseURL == "" {
		return fmt.Errorf("sp_base_url is required")
	}
	base, err := parseAbsoluteHTTPURL("sp_base_url", o.SPBaseURL)
	if err != nil {
		return err
	}
	if base.RawQuery != "" || strings.Contains(o.SPBaseURL, "#") || base.User != nil {
		return fmt.Errorf("sp_base_url %q must be an origin with no query, fragment or credentials", o.SPBaseURL)
	}
	if o.MCPURL == "" {
		return fmt.Errorf("mcp_url is required")
	}
	mcp, err := parseAbsoluteHTTPURL("mcp_url", o.MCPURL)
	if err != nil {
		return err
	}
	if mcp.RawQuery != "" || strings.Contains(o.MCPURL, "#") || mcp.User != nil {
		return fmt.Errorf("mcp_url %q must have no query, fragment or credentials", o.MCPURL)
	}
	if mcp.Scheme != base.Scheme || mcp.Host != base.Host {
		return fmt.Errorf("mcp_url %q must share sp_base_url's origin %s://%s", o.MCPURL, base.Scheme, base.Host)
	}
	if mcp.Path == "" || mcp.Path == "/" {
		return fmt.Errorf("mcp_url %q must name the MCP endpoint path", o.MCPURL)
	}
	if mcp.Path == OAuthPathPrefix || strings.HasPrefix(mcp.Path, OAuthPathPrefix+"/") ||
		mcp.Path == LoginPathPrefix || strings.HasPrefix(mcp.Path, LoginPathPrefix+"/") || mcp.Path == LogoutPath {
		return fmt.Errorf("mcp_url %q must not be a path the proxy serves itself", o.MCPURL)
	}
	if o.CodeTTL < minCodeTTL || o.CodeTTL > maxCodeTTL {
		return fmt.Errorf("code_ttl %s must be between %s and %s", o.CodeTTL, minCodeTTL, maxCodeTTL)
	}
	if o.RefreshAbsoluteLifetime <= 0 || o.RefreshAbsoluteLifetime > maxRefreshLife {
		return fmt.Errorf("refresh_absolute_lifetime %s must be positive and at most %s", o.RefreshAbsoluteLifetime, maxRefreshLife)
	}

	if len(o.SealingKeys) == 0 {
		return fmt.Errorf("sealing_keys requires at least one key")
	}
	sealing := make([][]byte, 0, len(o.SealingKeys))
	for i, s := range o.SealingKeys {
		k, err := decodeSealingKey(s)
		if err != nil {
			return fmt.Errorf("sealing_keys[%d]: %w", i, err)
		}
		sealing = append(sealing, k)
	}

	if len(o.Clients) == 0 {
		return fmt.Errorf("clients requires at least one client")
	}
	ids := make(map[string]bool, len(o.Clients))
	for i, c := range o.Clients {
		if err := c.validate(); err != nil {
			return fmt.Errorf("clients[%d]: %w", i, err)
		}
		if err := markUnique(ids, "clients id", c.ID); err != nil {
			return fmt.Errorf("clients[%d]: %w", i, err)
		}
	}

	for i, sub := range o.Denylist.Subjects {
		if strings.TrimSpace(sub) == "" {
			return fmt.Errorf("denylist.subjects[%d] must not be empty", i)
		}
	}
	o.sealing = sealing
	return nil
}

// decodeSealingKey reads a base64 (standard or URL alphabet, padded or not)
// 32-byte key, ignoring surrounding whitespace such as a file's final newline.
func decodeSealingKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("must not be empty")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != sealingKeyLen {
				return nil, fmt.Errorf("must decode to %d bytes, got %d", sealingKeyLen, len(b))
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("must be base64 encoded")
}

func (c OAuthClient) validate() error {
	if c.ID == "" || strings.ContainsAny(c.ID, " \t\r\n") {
		return fmt.Errorf("id is required and must not contain whitespace")
	}
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris requires at least one URI")
	}
	for i, raw := range c.RedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			return fmt.Errorf("redirect_uris[%d]: %w", i, err)
		}
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := parseAbsoluteHTTPURL("redirect URI", raw)
	if err != nil {
		return err
	}
	// ParseRequestURI keeps a "#..." in the path, so look for it in the text.
	if strings.Contains(raw, "#") || u.User != nil {
		return fmt.Errorf("%q must have no fragment or credentials", raw)
	}
	if u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%q: http is only allowed for localhost, 127.0.0.1 or [::1]", raw)
	}
	return nil
}

// IsLoopbackHost reports whether host names the loopback interface the way
// RFC 8252 section 7.3 allows for native app redirects.
func IsLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// OAuthEnabled reports whether the proxy acts as an OAuth server.
func (c *Config) OAuthEnabled() bool {
	return c.Inbound.OAuthServer != nil && !c.Inbound.OAuthServer.Disabled && c.Outbound.Token != nil
}

// validateOAuth checks inbound.oauth_server and outbound.token, which only
// make sense together, and what they must not collide with.
func (c *Config) validateOAuth() error {
	srv, tok := c.Inbound.OAuthServer, c.Outbound.Token
	switch {
	case srv == nil && tok == nil:
		return nil
	case srv == nil:
		return fmt.Errorf("outbound.token requires inbound.oauth_server")
	case tok == nil:
		return fmt.Errorf("inbound.oauth_server requires outbound.token")
	}
	if err := srv.validate(); err != nil {
		return fmt.Errorf("inbound.oauth_server: %w", err)
	}
	if err := tok.validate(); err != nil {
		return fmt.Errorf("outbound.token: %w", err)
	}

	auth := c.Inbound.Auth
	for i := range auth.JWT {
		if auth.JWT[i].Name == OAuthSourceName {
			return fmt.Errorf("inbound.auth.jwt[%d]: name %q is reserved for the tokens inbound.oauth_server issues", i, OAuthSourceName)
		}
		if l := auth.JWT[i].Login; l != nil && underOAuthPrefix(l.CallbackPath) {
			return fmt.Errorf("inbound.auth.jwt[%d]: login.callback_path %q is served by inbound.oauth_server", i, l.CallbackPath)
		}
	}
	if auth.SAML != nil && underOAuthPrefix(auth.SAML.ACSPath) {
		return fmt.Errorf("inbound.auth.saml: acs_path %q is served by inbound.oauth_server", auth.SAML.ACSPath)
	}
	return nil
}

func underOAuthPrefix(path string) bool {
	return path == OAuthPathPrefix || strings.HasPrefix(path, OAuthPathPrefix+"/")
}
