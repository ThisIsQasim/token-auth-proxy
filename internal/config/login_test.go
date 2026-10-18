package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validLoginSource() JWTSource {
	j := JWTSource{
		Issuer:           "https://idp.example.com",
		OIDCDiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		Login:            &JWTLogin{ClientID: "proxy", SPBaseURL: "https://proxy.example.com"},
	}
	j.applyDefaults()
	return j
}

func TestJWTLogin_Defaults(t *testing.T) {
	j := validLoginSource()
	require.NoError(t, j.validate())

	assert.Equal(t, "/oidc/callback", j.Login.CallbackPath)
	assert.Equal(t, "tap_id_token", j.Login.CookieName)
	assert.Equal(t, []string{"openid", "profile", "email"}, j.Login.Scopes)
	assert.Equal(t, []string{"proxy"}, j.Audiences, "audiences default to the client id, the aud of the ID token")
	assert.Empty(t, j.Login.TokenAuthMethod, "a public client has no token auth method")
	assert.Contains(t, j.Credentials, CredentialLocation{Location: "cookie", Name: "tap_id_token"})
	assert.Contains(t, j.Credentials, CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "}, "bearer tokens keep working")
}

func TestJWTLogin_ConfidentialDefaults(t *testing.T) {
	j := JWTSource{
		Issuer: "https://idp.example.com", OIDCDiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		Login: &JWTLogin{ClientID: "proxy", ClientSecret: "s", SPBaseURL: "https://proxy.example.com"},
	}
	j.applyDefaults()
	require.NoError(t, j.validate())
	assert.Equal(t, TokenAuthBasic, j.Login.TokenAuthMethod)
}

func TestJWTLogin_Validate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*JWTSource)
		errSub string
	}{
		{"jwks_url without discovery", func(j *JWTSource) { j.OIDCDiscoveryURL, j.JWKSURL = "", "https://idp.example.com/jwks" }, "oidc_discovery_url"},
		{"missing client_id", func(j *JWTSource) { j.Login.ClientID = "" }, "client_id"},
		{"audiences without client_id", func(j *JWTSource) { j.Audiences = []string{"other"} }, "audiences must contain"},
		{"missing sp_base_url", func(j *JWTSource) { j.Login.SPBaseURL = "" }, "sp_base_url"},
		{"relative callback", func(j *JWTSource) { j.Login.CallbackPath = "cb" }, "callback_path"},
		{"callback on login route", func(j *JWTSource) { j.Login.CallbackPath = "/_tap/login/x" }, "served by the proxy"},
		{"callback on healthz", func(j *JWTSource) { j.Login.CallbackPath = "/healthz" }, "served by the proxy"},
		{"no openid scope", func(j *JWTSource) { j.Login.Scopes = []string{"profile"} }, "openid"},
		{"auth method without secret", func(j *JWTSource) { j.Login.TokenAuthMethod = TokenAuthPost }, "token_auth_method"},
		{"bad auth method", func(j *JWTSource) {
			j.Login.ClientSecret, j.Login.TokenAuthMethod = "s", "private_key_jwt"
		}, "token_auth_method"},
		{"bad cookie name", func(j *JWTSource) { j.Login.CookieName = "a b" }, "cookie_name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := validLoginSource()
			tc.mutate(&j)
			err := j.validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errSub)
		})
	}
}

func TestInboundAuth_LoginCrossChecks(t *testing.T) {
	a := validLoginSource()
	b := validLoginSource()
	b.Name = "second"
	b.Login.CookieName = "other_cookie"

	t.Run("duplicate callback path", func(t *testing.T) {
		cfg := InboundAuthConfig{JWT: []JWTSource{a, b}}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "callback_path")
	})

	t.Run("duplicate cookie name", func(t *testing.T) {
		c := b
		c.Login = &JWTLogin{}
		*c.Login = *b.Login
		c.Login.CallbackPath, c.Login.CookieName = "/cb2", a.Login.CookieName
		cfg := InboundAuthConfig{JWT: []JWTSource{a, c}}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cookie_name")
	})

	t.Run("distinct sources are fine and counted", func(t *testing.T) {
		c := b
		c.Login = &JWTLogin{}
		*c.Login = *b.Login
		c.Login.CallbackPath = "/cb2"
		cfg := InboundAuthConfig{JWT: []JWTSource{a, c}}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, 2, cfg.LoginMethodCount())
	})

	t.Run("disabled source is not a login method", func(t *testing.T) {
		d := a
		d.Disabled = true
		assert.Equal(t, 0, InboundAuthConfig{JWT: []JWTSource{d}}.LoginMethodCount())
	})

	t.Run("saml collisions", func(t *testing.T) {
		saml := &SAMLSource{ACSPath: "/oidc/callback", SessionCookie: "saml_session"}
		cfg := InboundAuthConfig{JWT: []JWTSource{a}, SAML: saml}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "collides")
	})
}

func TestLoginPage_Validate(t *testing.T) {
	ok := InboundAuthConfig{LoginPage: &LoginPageConfig{CSS: "a { color: red; }"}}
	require.NoError(t, ok.Validate())

	for _, css := range []string{"</style><script>x</script>", "</STYLE >"} {
		bad := InboundAuthConfig{LoginPage: &LoginPageConfig{CSS: css}}
		err := bad.Validate()
		require.Error(t, err, css)
		assert.Contains(t, err.Error(), "login_page.css")
	}
}

func TestJWTLogin_Refresh(t *testing.T) {
	j := validLoginSource()
	assert.False(t, j.Login.Refresh)
	assert.Zero(t, j.Login.RefreshMaxAge)

	j = validLoginSource()
	j.Login.Refresh = true
	j.applyDefaults()
	require.NoError(t, j.validate())
	assert.Equal(t, 30*24*time.Hour, j.Login.RefreshMaxAge)
	assert.Equal(t, "tap_id_token_refresh", j.Login.RefreshCookieName())
	assert.NotContains(t, j.Credentials, CredentialLocation{Location: "cookie", Name: "tap_id_token_refresh"}, "the refresh cookie is never read as a credential")

	j = validLoginSource()
	j.Login.RefreshMaxAge = time.Hour
	assert.ErrorContains(t, j.validate(), "refresh_max_age only applies")

	j = validLoginSource()
	j.Login.Refresh, j.Login.RefreshMaxAge = true, -time.Hour
	assert.ErrorContains(t, j.validate(), "must not be negative")
}

func TestInboundAuth_RefreshCookieCollision(t *testing.T) {
	a := validLoginSource()
	a.Login.Refresh = true
	a.applyDefaults()
	b := validLoginSource()
	b.Name = "second"
	b.Login.CallbackPath = "/cb2"
	b.Login.CookieName = "tap_id_token_refresh"
	cfg := InboundAuthConfig{JWT: []JWTSource{a, b}}
	assert.ErrorContains(t, cfg.Validate(), "already used by another source")
}

func TestJWTLogin_CookieNameValidation(t *testing.T) {
	for name, ok := range map[string]bool{
		"tap_id_token": true, "my-session.v2": true, "A1!#$%&'*+^`|~": true,
		"my/session": false, "a(b)": false, "a@b": false, "a b": false, "é": false, "": true, // empty defaults
		"tap_login_state": false, "tap_login_method": false,
	} {
		j := validLoginSource()
		j.Login.CookieName = name
		if name == "" {
			j.Login.CookieName = "tap_id_token"
		}
		err := j.validate()
		if ok {
			assert.NoError(t, err, name)
		} else {
			assert.Error(t, err, name)
		}
	}
}
