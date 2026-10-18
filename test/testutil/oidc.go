package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenRequest records how the last /token call authenticated, so tests
// can assert a confidential client sent its secret and a public client
// did not.
type TokenRequest struct {
	ClientID     string
	AuthMethod   string // "basic" | "post" | "none"
	SecretOK     bool
	VerifierOK   bool
	GrantType    string
	RedirectURI  string
	CodeRedeemed bool
}

type oidcClient struct {
	secret string // empty means public: PKCE only
}

type oidcRefresh struct {
	clientID string
	used     bool
	revoked  bool
}

type oidcCode struct {
	clientID    string
	redirectURI string
	challenge   string
	nonce       string
	used        bool
}

// oidcState is the browser-login half of TestIDP: an authorization
// endpoint that redirects straight back (the "user" is already signed
// in as Subject) and a token endpoint that enforces client
// authentication and PKCE.
type oidcState struct {
	mu      sync.Mutex
	clients map[string]oidcClient
	codes   map[string]*oidcCode
	last    TokenRequest

	refreshOn     bool
	rotate        bool
	refreshSeq    int
	refreshCalls  int
	refreshDelay  time.Duration
	refreshTokens map[string]*oidcRefresh

	// Subject and Claims are what the next ID token carries; Claims are
	// merged over iss/aud/sub/exp/nonce so a test can override any of them.
	Subject string
	Claims  map[string]any

	// TTL is the ID token lifetime, default one hour.
	TTL time.Duration

	// SkipNonce makes the ID token omit the nonce, simulating a
	// non-conformant IdP.
	SkipNonce bool
}

func (i *TestIDP) oidc() *oidcState {
	i.oidcOnce.Do(func() {
		i.oidcSt = &oidcState{clients: map[string]oidcClient{}, codes: map[string]*oidcCode{}, refreshTokens: map[string]*oidcRefresh{}, Subject: "user-1", TTL: time.Hour}
	})
	return i.oidcSt
}

// RegisterClient registers an OIDC client. An empty secret makes it a
// public client that must use PKCE and send no secret.
func (i *TestIDP) RegisterClient(id, secret string) {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = oidcClient{secret: secret}
}

// SetLoginUser sets the subject and extra claims of the next ID tokens.
func (i *TestIDP) SetLoginUser(sub string, claims map[string]any) {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Subject, s.Claims = sub, claims
}

// SetLoginTTL sets the lifetime of the next ID tokens.
func (i *TestIDP) SetLoginTTL(d time.Duration) {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TTL = d
}

// OmitNonce makes later ID tokens carry no nonce claim.
func (i *TestIDP) OmitNonce() {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SkipNonce = true
}

// LastTokenRequest returns the most recent /token call.
func (i *TestIDP) LastTokenRequest() TokenRequest {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// AuthorizeURL is the IdP's authorization endpoint.
func (i *TestIDP) AuthorizeURL() string { return i.Server.URL + "/authorize" }

// TokenURL is the IdP's token endpoint.
func (i *TestIDP) TokenURL() string { return i.Server.URL + "/token" }

func (i *TestIDP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	s := i.oidc()
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")

	s.mu.Lock()
	_, ok := s.clients[q.Get("client_id")]
	s.mu.Unlock()
	if !ok || redirect == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// A public client must use PKCE; a confidential one may. Either way a
	// challenge that is present has to be S256.
	challenge := q.Get("code_challenge")
	if challenge != "" && q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid_request: code_challenge_method", http.StatusBadRequest)
		return
	}

	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	code := hex.EncodeToString(raw)
	s.mu.Lock()
	s.codes[code] = &oidcCode{clientID: q.Get("client_id"), redirectURI: redirect, challenge: challenge, nonce: q.Get("nonce")}
	s.mu.Unlock()

	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // test fixture; redirect_uri is the proxy callback under test
}

func (i *TestIDP) serveToken(w http.ResponseWriter, r *http.Request) {
	s := i.oidc()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	rec := TokenRequest{GrantType: r.PostForm.Get("grant_type"), RedirectURI: r.PostForm.Get("redirect_uri")}
	id, secret, basic := r.BasicAuth()
	switch {
	case basic:
		rec.AuthMethod = "basic"
	case r.PostForm.Get("client_secret") != "":
		rec.AuthMethod, id, secret = "post", r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	default:
		rec.AuthMethod, id = "none", r.PostForm.Get("client_id")
	}
	rec.ClientID = id

	s.mu.Lock()
	body, errCode, delay := i.tokenResponseLocked(s, r, &rec, id, secret)
	s.last = rec
	s.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if errCode != "" {
		tokenError(w, errCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, body)
}

// tokenResponseLocked handles one /token call with s.mu held. It returns
// either the response body or an OAuth error code, plus how long to
// delay the response.
func (i *TestIDP) tokenResponseLocked(s *oidcState, r *http.Request, rec *TokenRequest, id, secret string) (map[string]any, string, time.Duration) {
	client, ok := s.clients[id]
	if !ok {
		return nil, "invalid_client", 0
	}
	rec.SecretOK = client.secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(client.secret)) == 1
	if (client.secret != "" && !rec.SecretOK) || (client.secret == "" && secret != "") {
		return nil, "invalid_client", 0
	}

	switch rec.GrantType {
	case "refresh_token":
		s.refreshCalls++
		rt := s.refreshTokens[r.PostForm.Get("refresh_token")]
		if rt == nil || rt.clientID != id || rt.revoked || (s.rotate && rt.used) {
			return nil, "invalid_grant", 0
		}
		rt.used = true
		idToken, err := i.signIDToken(s, id, "")
		if err != nil {
			return nil, "server_error", 0
		}
		resp := map[string]any{"access_token": "at-refreshed", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken}
		if s.rotate {
			resp["refresh_token"] = s.newRefreshTokenLocked(id)
		}
		return resp, "", s.refreshDelay

	case "authorization_code":
		code := s.codes[r.PostForm.Get("code")]
		if code == nil || code.used || code.clientID != id || code.redirectURI != rec.RedirectURI {
			return nil, "invalid_grant", 0
		}
		code.used = true
		rec.CodeRedeemed = true

		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		rec.VerifierOK = code.challenge != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == code.challenge
		if code.challenge != "" && !rec.VerifierOK {
			return nil, "invalid_grant", 0
		}
		if client.secret == "" && code.challenge == "" {
			return nil, "invalid_grant", 0
		}

		nonce := code.nonce
		if s.SkipNonce {
			nonce = ""
		}
		idToken, err := i.signIDToken(s, id, nonce)
		if err != nil {
			return nil, "server_error", 0
		}
		resp := map[string]any{"access_token": "at-" + code.nonce, "token_type": "Bearer", "expires_in": 3600, "id_token": idToken}
		if s.refreshOn {
			resp["refresh_token"] = s.newRefreshTokenLocked(id)
		}
		return resp, "", 0
	}
	return nil, "unsupported_grant_type", 0
}

func (s *oidcState) newRefreshTokenLocked(clientID string) string {
	s.refreshSeq++
	tok := "rt-" + strconv.Itoa(s.refreshSeq)
	s.refreshTokens[tok] = &oidcRefresh{clientID: clientID}
	return tok
}

// signIDToken mints the next ID token for clientID; an empty nonce omits
// the claim, as a refresh response does.
func (i *TestIDP) signIDToken(s *oidcState, clientID, nonce string) (string, error) {
	claims := jwt.MapClaims{
		"iss": i.Issuer,
		"aud": clientID,
		"sub": s.Subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(s.TTL).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range s.Claims {
		claims[k] = v
	}

	i.mu.Lock()
	kp := i.kp
	i.mu.Unlock()
	tok := jwt.NewWithClaims(kp.method, claims)
	tok.Header["kid"] = kp.kid
	return tok.SignedString(kp.priv)
}

// EnableRefresh makes the IdP issue refresh tokens on the code exchange.
// With rotate, each redemption returns a new refresh token and the old
// one stops working, like a rotating IdP.
func (i *TestIDP) EnableRefresh(rotate bool) {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshOn, s.rotate = true, rotate
}

// RefreshCalls is how many refresh_token grants the IdP has received.
func (i *TestIDP) RefreshCalls() int {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshCalls
}

// RevokeRefreshTokens makes every issued refresh token invalid.
func (i *TestIDP) RevokeRefreshTokens() {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rt := range s.refreshTokens {
		rt.revoked = true
	}
}

// SetRefreshDelay delays refresh responses, widening the window in which
// parallel requests can pile up behind one redemption.
func (i *TestIDP) SetRefreshDelay(d time.Duration) {
	s := i.oidc()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshDelay = d
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	writeJSON(w, map[string]string{"error": code})
}

// MintLoginToken signs an ID token as the IdP would return for clientID,
// for tests that need one without running the flow.
func (i *TestIDP) MintLoginToken(tb testing.TB, clientID string, ttl time.Duration, extra map[string]any) string {
	tb.Helper()
	claims := jwt.MapClaims{"iss": i.Issuer, "aud": clientID, "sub": "user-1", "exp": time.Now().Add(ttl).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	return i.Sign(tb, claims)
}

func writeJSON(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
