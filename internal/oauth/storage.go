package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

var (
	errNotFound = errors.New("not found")
	errExpired  = errors.New("expired")
	errDisabled = errors.New("oauth server is not enabled")
)

// storage is op.Storage with nothing stored. Login requests, codes and
// refresh tokens are sealed values the library hands back to us, so every
// lookup is a decryption; keys and clients are fixed when the provider is
// built; and lifetimes and the denylist are read from the live config, so
// a reload takes effect without rebuilding anything.
type storage struct {
	sealer  *sealer
	crypto  op.Crypto
	keys    *keyManager
	clients map[string]*client
	issuer  string
	live    func() *config.Config // the current config, nil when the server is off
	now     func() time.Time
}

var (
	_ op.Storage                        = (*storage)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*storage)(nil)
)

// settings returns the live server and token config, or errDisabled.
func (s *storage) settings() (*config.OAuthServerConfig, *config.TokenConfig, error) {
	cfg := s.live()
	if cfg == nil || !cfg.OAuthEnabled() {
		return nil, nil, errDisabled
	}
	return cfg.Inbound.OAuthServer, cfg.Outbound.Token, nil
}

func (s *storage) denied(sub string) bool {
	srv, _, err := s.settings()
	return err != nil || srv.Denylist.Contains(sub)
}

func (s *storage) Health(context.Context) error {
	_, _, err := s.settings()
	return err
}

// ---- login requests and codes ----

func (s *storage) CreateAuthRequest(_ context.Context, r *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	_, tok, err := s.settings()
	if err != nil {
		return nil, err
	}
	// Checks the library does not make, or makes more loosely. They run after its
	// own validation, so the client and redirect_uri are known to be well formed.
	if c, ok := s.lookupClient(r.ClientID); !ok || !c.allowsRedirect(r.RedirectURI) {
		return nil, oidc.ErrInvalidRequestRedirectURI().WithDescription("The requested redirect_uri is not registered for this client.")
	}
	if r.CodeChallenge == "" || r.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE is required: send a code_challenge with code_challenge_method=S256.")
	}
	d := reqData{
		ClientID: r.ClientID, RedirectURI: r.RedirectURI, State: r.State, Nonce: r.Nonce,
		Scopes: r.Scopes, Challenge: r.CodeChallenge, Method: string(r.CodeChallengeMethod),
		Exp: s.now().Add(pendingTTL).Unix(),
	}
	id, err := s.sealer.seal(kindPending, d)
	if err != nil {
		return nil, err
	}
	return &authReq{d: d, id: id, audience: tok.Audience}, nil
}

// AuthRequestByID opens a login request. Only a finished login (kindDone)
// reports Done; a pending one is returned as not done, which the library
// answers with an interaction_required error and never a code.
func (s *storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	_, tok, err := s.settings()
	if err != nil {
		return nil, err
	}
	var d reqData
	done := true
	if err := s.sealer.open(kindDone, id, &d); err != nil {
		done = false
		if err := s.sealer.open(kindPending, id, &d); err != nil {
			return nil, errNotFound
		}
	}
	if s.now().Unix() > d.Exp {
		return nil, errExpired
	}
	return &authReq{d: d, id: id, audience: tok.Audience, done: done}, nil
}

// SaveAuthCode has nothing to save: the code is the encrypted ID of the
// finished login, so AuthRequestByCode can recover it.
func (s *storage) SaveAuthCode(context.Context, string, string) error { return nil }

func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	id, err := s.crypto.Decrypt(code)
	if err != nil {
		return nil, errNotFound
	}
	req, err := s.AuthRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if !req.Done() {
		return nil, errNotFound
	}
	// Someone put on the denylist between logging in and exchanging the code
	// gets no tokens.
	if s.denied(req.GetSubject()) {
		return nil, errNotFound
	}
	return req, nil
}

func (s *storage) DeleteAuthRequest(context.Context, string) error { return nil }

// ---- tokens ----

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *storage) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	_, tok, err := s.settings()
	if err != nil {
		return "", time.Time{}, err
	}
	return randomID(), s.now().Add(tok.AccessTokenTTL), nil
}

func (s *storage) CreateAccessAndRefreshTokens(_ context.Context, req op.TokenRequest, _ string) (string, string, time.Time, error) {
	srv, tok, err := s.settings()
	if err != nil {
		return "", "", time.Time{}, err
	}
	var d refreshData
	switch r := req.(type) {
	case *authReq:
		d = refreshData{
			Sub: r.d.Sub, Email: r.d.Email, Groups: r.d.Groups, Mode: r.d.Mode,
			ClientID: r.d.ClientID, Scopes: r.d.Scopes, AuthTime: r.d.AuthTime,
			Exp: time.Unix(r.d.AuthTime, 0).Add(srv.RefreshAbsoluteLifetime).Unix(),
		}
	case *refreshReq:
		d = r.d // the lifetime is absolute: refreshing does not extend it
	default:
		return "", "", time.Time{}, fmt.Errorf("unsupported token request %T", req)
	}
	refresh, err := s.sealer.seal(kindRefresh, d)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return randomID(), refresh, s.now().Add(tok.AccessTokenTTL), nil
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	_, tok, err := s.settings()
	if err != nil {
		return nil, err
	}
	var d refreshData
	if err := s.sealer.open(kindRefresh, token, &d); err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if s.now().Unix() > d.Exp || s.denied(d.Sub) {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshReq{d: d, audience: tok.Audience}, nil
}

func (s *storage) GetRefreshTokenInfo(_ context.Context, _ string, token string) (string, string, error) {
	var d refreshData
	if err := s.sealer.open(kindRefresh, token, &d); err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	sum := sha256.Sum256([]byte(token))
	return d.Sub, hex.EncodeToString(sum[:8]), nil
}

// TerminateSession and RevokeToken do nothing: there is no session to end
// and nothing stored to revoke. A person is cut off with the denylist.
func (s *storage) TerminateSession(context.Context, string, string) error { return nil }

func (s *storage) RevokeToken(context.Context, string, string, string) *oidc.Error { return nil }

// ---- keys ----

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) { return s.keys.signing(), nil }

func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (s *storage) KeySet(context.Context) ([]op.Key, error) { return s.keys.keySet(), nil }

// ---- clients ----

func (s *storage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	c, ok := s.lookupClient(id)
	if !ok {
		return nil, errNotFound
	}
	return c, nil
}

// AuthorizeClientIDSecret always fails: every client is public.
func (s *storage) AuthorizeClientIDSecret(context.Context, string, string) error {
	return errors.New("clients have no secret")
}

// ---- claims ----

// GetPrivateClaimsFromRequest puts the groups and email of the login into
// the access token. The names are fixed; which login claim feeds each is
// the claims setting.
func (s *storage) GetPrivateClaimsFromRequest(_ context.Context, req op.TokenRequest, _ []string) (map[string]any, error) {
	claims := map[string]any{}
	var email string
	var groups []string
	switch r := req.(type) {
	case *authReq:
		email, groups = r.d.Email, r.d.Groups
	case *refreshReq:
		email, groups = r.d.Email, r.d.Groups
	default:
		return nil, fmt.Errorf("unsupported token request %T", req)
	}
	if email != "" {
		claims["email"] = email
	}
	claims["groups"] = append([]string{}, groups...)
	return claims, nil
}

func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

func (s *storage) SetUserinfoFromToken(context.Context, *oidc.UserInfo, string, string, string) error {
	return nil
}

func (s *storage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return nil
}

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("unsupported")
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("unsupported")
}
