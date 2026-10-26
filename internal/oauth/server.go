package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// supportedScopes are the scopes the server grants and advertises. groups is
// the one custom scope: asking for it is how a client gets the groups claim
// some providers want requested explicitly; the claim is always issued.
var supportedScopes = []string{"openid", "profile", "email", "offline_access", "groups"}

// server is the provider and everything built from the configuration it
// was made from. It is replaced, not changed, when that configuration does.
type server struct {
	provider    *op.Provider
	storage     *storage
	handler     http.Handler
	sealer      *sealer
	keys        *keyManager
	issuer      string
	callbackURL string
	metadata    []byte
	fingerprint string
}

// Registry owns the server and rebuilds it when its configuration changes,
// like the SAML and JWT registries do. The denylist and lifetimes are not
// part of what it was built from, so they apply from the live config.
type Registry struct {
	logger *slog.Logger

	live atomic.Pointer[config.Config]
	seen atomic.Pointer[config.Config]
	srv  atomic.Pointer[server]

	mu sync.Mutex
}

// NewRegistry returns a Registry with nothing built; the first Reconcile
// builds the server if the configuration enables it.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{logger: logger}
}

// Reconcile brings the server in line with cfg: built when enabled, torn
// down when not, rebuilt when what it is built from changed.
func (r *Registry) Reconcile(cfg *config.Config) {
	if r.seen.Load() == cfg {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen.Load() == cfg {
		return
	}
	r.live.Store(cfg)

	if !cfg.OAuthEnabled() {
		if r.srv.Swap(nil) != nil {
			r.logger.Info("oauth server disabled")
		}
		r.seen.Store(cfg)
		return
	}
	fp := fingerprint(cfg)
	if cur := r.srv.Load(); cur != nil && cur.fingerprint == fp {
		r.seen.Store(cfg)
		return
	}
	srv, err := r.build(cfg, fp)
	if err != nil {
		// Keep serving nothing rather than the previous server with keys the
		// operator has just replaced; the error is the operator's to act on.
		r.logger.Error("oauth server not built", "err", err)
		r.srv.Store(nil)
		r.seen.Store(cfg)
		return
	}
	r.srv.Store(srv)
	r.seen.Store(cfg)
	r.logger.Info("oauth server built", "issuer", srv.issuer, "clients", len(cfg.Inbound.OAuthServer.Clients))
}

// fingerprint covers everything the server is built from. The denylist,
// lifetimes and claim names are deliberately absent: they are read live.
func fingerprint(cfg *config.Config) string {
	srv, tok := cfg.Inbound.OAuthServer, cfg.Outbound.Token
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			_, _ = fmt.Fprintf(h, "%d:%s|", len(p), p)
		}
	}
	write(srv.SPBaseURL, srv.MCPURL, tok.Audience)
	for _, k := range tok.SigningKeys {
		write("sig", k.KID, k.PrivateKey)
	}
	for _, k := range srv.SealingKeys {
		write("seal", k)
	}
	for _, c := range srv.Clients {
		write(append([]string{"client", c.ID}, c.RedirectURIs...)...)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (r *Registry) build(cfg *config.Config, fp string) (*server, error) {
	srvCfg, tok := cfg.Inbound.OAuthServer, cfg.Outbound.Token

	keys, err := newKeyManager(tok.Keys())
	if err != nil {
		return nil, err
	}
	sl, err := newSealer(srvCfg.SealingKeyBytes())
	if err != nil {
		return nil, err
	}

	// The library encrypts authorization codes with its own key. Derive it
	// from the first sealing key so it needs no setting of its own.
	mac := hmac.New(sha256.New, srvCfg.SealingKeyBytes()[0])
	mac.Write([]byte("tap-oauth authorization code"))
	var cryptoKey [32]byte
	copy(cryptoKey[:], mac.Sum(nil))

	issuer := srvCfg.Issuer()
	clients := make(map[string]*client, len(srvCfg.Clients))
	for _, c := range srvCfg.Clients {
		clients[c.ID] = &client{cfg: c, issuer: issuer}
	}
	st := &storage{
		sealer: sl, crypto: op.NewAES256GCMCrypto(cryptoKey, ""), keys: keys, clients: clients,
		live: r.live.Load, now: time.Now,
	}

	opts := []op.Option{
		op.WithLogger(r.logger),
		// The default token path is "oauth/token"; keep every route one level
		// under the issuer.
		op.WithCustomEndpoints(op.NewEndpoint("authorize"), op.NewEndpoint("token"), op.NewEndpoint("userinfo"),
			op.NewEndpoint("revoke"), op.NewEndpoint("end_session"), op.NewEndpoint("jwks.json")),
	}
	if strings.HasPrefix(issuer, "http://") {
		opts = append(opts, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(&op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       supportedScopes,
	}, st, op.StaticIssuer(issuer), opts...)
	if err != nil {
		return nil, fmt.Errorf("build provider: %w", err)
	}

	metadata, err := json.Marshal(map[string]any{
		"resource":                 srvCfg.MCPURL,
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         supportedScopes,
	})
	if err != nil {
		return nil, err
	}

	return &server{
		provider:    provider,
		storage:     st,
		handler:     http.StripPrefix(config.OAuthPathPrefix, provider),
		sealer:      sl,
		keys:        keys,
		issuer:      issuer,
		callbackURL: provider.AuthorizationEndpoint().Absolute(issuer) + "/callback",
		metadata:    metadata,
		fingerprint: fp,
	}, nil
}

// Enabled reports whether a server is currently built.
func (r *Registry) Enabled() bool { return r.srv.Load() != nil }

// Keyfunc verifies the tokens this server issues, for the JWT leg. It looks
// the server up on every call, so a rotation applies at once.
func (r *Registry) Keyfunc() jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		s := r.srv.Load()
		if s == nil {
			return nil, errDisabled
		}
		return s.keys.keyfunc()(t)
	}
}

// Denied reports whether sub is on the live denylist.
func (r *Registry) Denied(sub string) bool {
	cfg := r.live.Load()
	return cfg == nil || !cfg.OAuthEnabled() || cfg.Inbound.OAuthServer.Denylist.Contains(sub)
}

// ServeHTTP serves every route under OAuthPathPrefix except the login hand
// off, which needs the proxy's own authentication and is ServeLogin.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s := r.srv.Load()
	if s == nil {
		http.NotFound(w, req)
		return
	}
	if req.URL.Path == config.OAuthPathPrefix+"/protected-resource" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(s.metadata)
		return
	}
	s.handler.ServeHTTP(w, req)
}

// Authenticator authenticates the person behind a browser request with the
// proxy's own login methods. If it identifies them it calls allow, once,
// with who they are and whether the ACL lets them use the MCP endpoint;
// otherwise it has already responded (an IdP redirect, a login page, an
// error) and allow is never called.
type Authenticator func(w http.ResponseWriter, r *http.Request, allow func(id Identity, mcpAllowed bool))

// ServeLogin is the hand-off between the proxy's login and the OAuth flow.
// The library has sent the browser here with a sealed login request; once
// the person is authenticated this seals the finished login and sends the
// browser back to the library, which turns it into an authorization code.
// Nothing about who the person is is taken from the request: the identity
// comes only from authenticate.
func (r *Registry) ServeLogin(w http.ResponseWriter, req *http.Request, authenticate Authenticator) {
	s := r.srv.Load()
	cfg := r.live.Load()
	if s == nil || cfg == nil || !cfg.OAuthEnabled() {
		http.NotFound(w, req)
		return
	}
	// The id travels in the URL: keep it out of caches and Referer headers.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := req.URL.Query().Get("id")
	var d reqData
	if err := s.sealer.open(kindPending, id, &d); err != nil || time.Now().Unix() > d.Exp {
		r.logger.Info("oauth login rejected", "reason", "invalid or expired login request")
		http.Error(w, "this login request is invalid or has expired; start again from your client", http.StatusBadRequest)
		return
	}

	authenticate(w, req, func(who Identity, mcpAllowed bool) {
		sub, email, groups, err := who.extract(cfg.Outbound.Token.Claims)
		if err != nil {
			r.logger.Warn("oauth login rejected", "reason", "no subject", "mode", who.Mode, "err", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Denied(sub) || !mcpAllowed {
			reason := "acl"
			if r.Denied(sub) {
				reason = "denylist"
			}
			r.logger.Info("oauth login rejected", "reason", reason, "subject", truncate(sub, maxLoggedSubject), "client", d.ClientID)
			http.Error(w, "forbidden: this account may not use this service", http.StatusForbidden)
			return
		}

		now := time.Now()
		d.Sub, d.Email, d.Groups, d.Mode = sub, email, groups, who.Mode
		d.AuthTime = now.Unix()
		d.Exp = now.Add(cfg.Inbound.OAuthServer.CodeTTL).Unix()
		done, err := s.sealer.seal(kindDone, d)
		if err != nil {
			r.logger.Error("oauth login failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		r.logger.Info("oauth login", "subject", truncate(sub, maxLoggedSubject), "mode", who.Mode, "client", d.ClientID)
		http.Redirect(w, req, s.callbackURL+"?id="+url.QueryEscape(done), http.StatusFound)
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
