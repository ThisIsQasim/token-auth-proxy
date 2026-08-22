package config

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Defaults for fields left zero-valued in a JWTSource or SAMLSource.
const (
	defaultJWKSCacheTTL        = 5 * time.Minute  // matches Envoy jwt_authn's cache_duration default
	defaultClockSkew           = 60 * time.Second // matches Envoy jwt_authn's clock_skew default
	defaultSessionDuration     = 12 * time.Hour   // typical enterprise SSO session length
	defaultIDPMetadataCacheTTL = 1 * time.Hour    // SAML IdP metadata (signing certs) rotates far less often than JWKS
)

// minSessionSigningKeyLen is the shortest secret accepted for the HS256
// session cookie signature. Mirrors JWTSource.applyDefaults' fail-closed
// philosophy: a too-short secret is a config error caught at load time,
// not a silently weak signature discovered later.
const minSessionSigningKeyLen = 32

// defaultAlgorithm is used when a JWTSource doesn't list any Algorithms.
const defaultAlgorithm = "RS256"

// defaultBasicRealm is the realm advertised in the WWW-Authenticate
// challenge when a BasicSource doesn't name one. It's user-visible — a
// browser prints it verbatim in its login dialog — which is exactly why
// the field exists to be overridden.
const defaultBasicRealm = "restricted"

// allowedAlgorithms is the set of JWT signing algorithms a source may
// configure. No HS* (no shared-secret support for JWT sources, since
// key material only ever comes from a JWKS/OIDC discovery URL — there's
// nothing to share a secret with); "none" is never valid regardless of
// what's fetched.
var allowedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// allowedCredentialLocations is the set of places a JWTSource's
// Credentials entries may look for a token in an incoming request.
var allowedCredentialLocations = map[string]bool{"header": true, "cookie": true, "query": true}

// InboundConfig groups configuration about requests arriving at the
// proxy. Auth is its only facet today; other inbound concerns (rate
// limiting, IP allowlisting, ...) would live alongside it here later
// without disturbing Config's top-level shape.
type InboundConfig struct {
	Auth InboundAuthConfig `yaml:"auth,omitempty"`
}

// applyDefaults delegates to Auth; Inbound has no other facets yet.
func (i *InboundConfig) applyDefaults() {
	i.Auth.applyDefaults()
}

// Validate delegates to Auth; Inbound has no other facets yet.
func (i *InboundConfig) Validate() error {
	return i.Auth.Validate()
}

// OutboundConfig mirrors InboundConfig for the backend leg. Reserved —
// designed in a later pass (credential rewriting, e.g. verify an
// inbound SAML assertion and mint an outbound OIDC-style JWT to attach
// when forwarding). Deliberately empty this pass.
type OutboundConfig struct{}

// InboundAuthConfig has no separate enabled/disabled switch of its own:
// whether verification is enforced is purely inferred from whether at
// least one non-Disabled source exists (see Enabled below), not a
// second toggle that could disagree with the source list. To stage a
// fully-written source list without going live, mark each entry
// disabled: true individually — the same field that also lets an
// operator pull just one source out of rotation later — rather than
// flipping one section-level flag that could contradict it.
//
// JWT is a list (multiple trusted issuers are entirely practical: a
// bearer token carries its own iss claim, so JWTSourcesByIssuer can
// route to the right source(s) after the fact, regardless of which
// single backend Target every request ultimately forwards to). More
// than one source may share an Issuer — e.g. rolling a JWKS/CA
// migration, or trusting two independent key sets under one nominal
// issuer — in which case JWTSourcesByIssuer returns all of them, in
// config order, and the JWT middleware tries each in turn until one
// fully verifies the token (see enforceJWT). SAML is at
// most one source, deliberately not a list: unlike a bearer token, a
// SAML SP-initiated redirect has to pick an IdP to send the browser to
// before any credential exists, and with only one Target and no
// per-path/per-route concept in this proxy, there's no signal available
// at that point to choose among multiple IdPs by (no path-based or
// host-based routing, and an IdP-discovery step was explicitly ruled
// out). A single optional source sidesteps needing that selection logic
// at all — see the Handoff notes for where per-path routing would need
// to be designed if multi-IdP SAML is ever wanted later.
//
// Basic is likewise at most one source, but for its own reason rather
// than SAML's: a Basic challenge names exactly one realm, and with no
// per-path routing there's nothing to pick a second realm's user list
// by (two user lists guarding the same single Target is one user
// list). Unlike JWT and SAML, it has no Name of its own — there's only
// ever one of it, so logs identify it as "basic" and there's nothing
// for Validate's uniqueness check to disambiguate.
type InboundAuthConfig struct {
	JWT   []JWTSource  `yaml:"jwt,omitempty"`
	SAML  *SAMLSource  `yaml:"saml,omitempty"`
	Basic *BasicSource `yaml:"basic,omitempty"`
}

// applyDefaults fills in every JWT source's own defaults, and SAML's
// and Basic's if configured.
func (a *InboundAuthConfig) applyDefaults() {
	for i := range a.JWT {
		a.JWT[i].applyDefaults()
	}
	if a.SAML != nil {
		a.SAML.applyDefaults()
	}
	if a.Basic != nil {
		a.Basic.applyDefaults()
	}
}

// Enabled reports whether the proxy has anything to verify requests
// against: true iff JWTEnabled or SAMLEnabled. This is the single place
// that logic lives — the config watcher's reload log calls this rather
// than re-deriving it, and it's what makes "enabled with nothing that
// can actually authenticate anyone" a structurally impossible state
// rather than something Validate has to separately catch: Enabled is
// defined in terms of "does a working source exist," so it can never
// report true while none does.
//
// Enabled alone is deliberately too broad to gate a single enforcement
// mode on: it's true for a JWT-only, a SAML-only, a Basic-only, or any
// combined config alike. Code that needs to know which mode(s) are
// actually active must use JWTEnabled/SAMLEnabled/BasicEnabled instead
// — see cmd/token-auth-proxy/main.go and internal/authn.NewMiddleware,
// which composes all three.
func (a InboundAuthConfig) Enabled() bool {
	return a.JWTEnabled() || a.SAMLEnabled() || a.BasicEnabled()
}

// JWTEnabled reports whether at least one non-Disabled JWT source
// exists — i.e. whether JWT verification is being enforced. Narrower
// than Enabled: a configuration with only a SAML source is Enabled but
// not JWTEnabled.
func (a InboundAuthConfig) JWTEnabled() bool {
	for _, j := range a.JWT {
		if !j.Disabled {
			return true
		}
	}
	return false
}

// SAMLEnabled reports whether the SAML source is configured and not
// Disabled — i.e. whether interactive SAML SP login (ACS route,
// SP-initiated redirects, session cookies) is being enforced. Narrower
// than Enabled, symmetric with JWTEnabled: a JWT-only configuration is
// Enabled but not SAMLEnabled.
func (a InboundAuthConfig) SAMLEnabled() bool {
	return a.SAML != nil && !a.SAML.Disabled
}

// BasicEnabled reports whether the Basic source is configured and not
// Disabled — i.e. whether username/password verification is being
// enforced. Narrower than Enabled, symmetric with JWTEnabled and
// SAMLEnabled.
func (a InboundAuthConfig) BasicEnabled() bool {
	return a.Basic != nil && !a.Basic.Disabled
}

// markUnique records val as seen under label in seen, or returns an
// error if it was already there. Shared by Validate's name uniqueness
// check (across JWT sources and the single SAML source) so the
// "already used by another source" message and bookkeeping aren't
// repeated per field.
func markUnique(seen map[string]bool, label, val string) error {
	if seen[val] {
		return fmt.Errorf("%s %q is already used by another source", label, val)
	}
	seen[val] = true
	return nil
}

// Validate validates every JWT source, the SAML source and the Basic
// source (if any) unconditionally — a source is either well-formed or
// it isn't, regardless of whether it or any sibling happens to be
// Disabled right now — then cross-checks that Name isn't reused
// between JWT sources and the SAML source. Name defaults to a source's
// own Issuer (see JWTSource.applyDefaults/SAMLSource.applyDefaults),
// so this is a no-op to satisfy in the common case (each source names
// a distinct issuer) and only demands an explicit, distinct name once
// two sources deliberately share an Issuer (see JWTSourcesByIssuer).
// Basic takes no part in this check: it has no Name, since there's
// only ever one of it. There's no acs_path/session_cookie uniqueness
// check to make either, since at most one SAML source can ever exist.
func (a *InboundAuthConfig) Validate() error {
	names := make(map[string]bool, len(a.JWT)+1)

	for i := range a.JWT {
		j := &a.JWT[i]
		if err := j.validate(); err != nil {
			return fmt.Errorf("inbound.auth.jwt[%d]: %w", i, err)
		}
		if err := markUnique(names, "name", j.Name); err != nil {
			return fmt.Errorf("inbound.auth.jwt[%d]: %w", i, err)
		}
	}

	if a.SAML != nil {
		if err := a.SAML.validate(); err != nil {
			return fmt.Errorf("inbound.auth.saml: %w", err)
		}
		if err := markUnique(names, "name", a.SAML.Name); err != nil {
			return fmt.Errorf("inbound.auth.saml: %w", err)
		}

		// A JWT source reading its bearer token from the same cookie the
		// SAML session lives in would make credential extraction pick up
		// a SAML session token and route it by its (SAML-issued) iss
		// claim — the two auth legs would silently fight over one
		// cookie. There's no sensible interpretation, so reject it here
		// rather than let it surface as a confusing runtime rejection.
		for i := range a.JWT {
			for _, c := range a.JWT[i].Credentials {
				if c.Location == "cookie" && c.Name == a.SAML.SessionCookie {
					return fmt.Errorf("inbound.auth.jwt[%d]: credentials cookie %q collides with inbound.auth.saml.session_cookie", i, c.Name)
				}
			}
		}
	}

	if a.Basic != nil {
		if err := a.Basic.validate(); err != nil {
			return fmt.Errorf("inbound.auth.basic: %w", err)
		}

		// A JWT source reading the Authorization header with no prefix
		// extracts *whatever* is in it — including a Basic credential,
		// which it would then reject as a malformed token. The
		// middleware resolves that at runtime by letting Basic decide
		// first, but a config where the two legs are reaching for the
		// same header with no way to tell the schemes apart is a
		// mistake worth naming here rather than papering over: same
		// reasoning as the jwt-cookie/saml-session-cookie collision
		// above.
		if a.BasicEnabled() {
			for i := range a.JWT {
				if a.JWT[i].Disabled {
					continue
				}
				for _, c := range a.JWT[i].Credentials {
					if c.Location == "header" && strings.EqualFold(c.Name, "Authorization") && c.Prefix == "" {
						return fmt.Errorf("inbound.auth.jwt[%d]: credentials header %q with no prefix collides with inbound.auth.basic; give it a prefix (e.g. %q)", i, c.Name, "Bearer ")
					}
				}
			}
		}
	}

	return nil
}

// JWTSourcesByIssuer returns every enabled JWT source trusting iss, in
// the order they appear under inbound.auth.jwt. Disabled entries are
// skipped — that's the actual behavioral meaning of the field. Usually
// this is zero or one source; more than one is deliberate (see this
// type's own doc comment) and the caller — enforceJWT — tries each
// returned source in order, moving on only if the previous one's
// entire verification (signature, exp/nbf, audiences, algorithms)
// failed, so the returned order is itself part of the behavior, not
// just a convenience.
//
// There's no SAML equivalent of this lookup: with at most one SAML
// source, a caller already knows which source it's dealing with — it's
// InboundAuthConfig.SAML, or there isn't one — so there's nothing to
// disambiguate by issuer in the first place.
//
// Called once per JWT-authenticated request (see enforceJWT), so the
// zero/one-match case - the overwhelming majority - is worth keeping
// allocation-free: it's answered by reslicing directly into a.JWT's
// own backing array rather than appending into a fresh one. That's
// safe only because InboundAuthConfig is never mutated after
// construction (config.Watcher publishes a brand-new *Config on every
// reload rather than mutating a published one - see Registry's doc
// comment for the identical invariant) - the returned slice aliases
// a.JWT, so a caller that mutated it would corrupt the live config.
// Two or more matches falls back to a fresh copy, both because that
// path is rare enough that the allocation doesn't matter and because
// a real slice keeps the result independent of a.JWT's element order.
func (a InboundAuthConfig) JWTSourcesByIssuer(iss string) []JWTSource {
	first := -1
	n := 0
	for i := range a.JWT {
		if !a.JWT[i].Disabled && a.JWT[i].Issuer == iss {
			if n == 0 {
				first = i
			}
			n++
		}
	}

	switch n {
	case 0:
		return nil
	case 1:
		return a.JWT[first : first+1]
	}

	matches := make([]JWTSource, 0, n)
	for i := range a.JWT {
		if !a.JWT[i].Disabled && a.JWT[i].Issuer == iss {
			matches = append(matches, a.JWT[i])
		}
	}
	return matches
}

// JWTSource describes one trusted JWT issuer: where to fetch its key
// material, which algorithms/audiences are acceptable, and where in an
// incoming request to look for the token itself. JWTSource and
// SAMLSource are separate types, not one shared type with a
// discriminator field — a JWT entry simply cannot carry SAML-only
// fields, or vice versa, so there's no "wrong fields for this type" of
// validation to write.
type JWTSource struct {
	// Name identifies this source in logs/errors and is what Validate
	// requires be unique across JWT+SAML — not Issuer. Optional: it
	// defaults to this source's own Issuer (see applyDefaults), so the
	// common case (one source per issuer) never needs it written down.
	// An explicit Name is only required once two sources deliberately
	// share an Issuer, to give each a distinct identity — see this
	// package's InboundAuthConfig doc comment for why that's supported
	// at all, and JWTSourcesByIssuer for how such sources are tried.
	Name     string `yaml:"name,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty"` // default false (Go's zero value); excludes just this source from lookup/routing without affecting any other source
	Issuer   string `yaml:"issuer"`             // required — the routing key once a credential's been extracted; need not be unique (see Name)

	Audiences        []string             `yaml:"audiences,omitempty"`   // if set, token's aud must contain one of these
	Credentials      []CredentialLocation `yaml:"credentials,omitempty"` // tried in order, first non-empty wins; defaults to [{header, Authorization, "Bearer "}] if omitted
	JWKSURL          string               `yaml:"jwks_url,omitempty"`    // exactly one of JWKSURL/OIDCDiscoveryURL
	OIDCDiscoveryURL string               `yaml:"oidc_discovery_url,omitempty"`

	// CACert is an optional PEM-encoded (or that same PEM, base64-encoded
	// — see ParseCACertPool) CA bundle used to verify the TLS
	// certificate of this source's jwks_url/oidc_discovery_url (and, for
	// a discovery URL, the jwks_uri it resolves to). Empty — the default
	// — means the system trust store, exactly as before.
	//
	// It *replaces* the system trust store for those endpoints rather
	// than extending it; see ParseCACertPool for why. The scope is
	// deliberately per-source and confined to key-material fetches: the
	// backend leg (Config.Target) and the SAML IdP metadata fetch are
	// separate trust decisions and are unaffected.
	//
	// PEM content rather than a path, matching SPCert: a path is written
	// as "${file:/var/run/secrets/.../ca.crt}" (see interpolate.go),
	// which turns an unreadable file into a config-load error, and —
	// because the resolved content lands here, inside the resolver
	// fingerprint — makes a rotated CA rebuild the resolver on the next
	// reload. A bare path field would do neither.
	CACert string `yaml:"ca_cert,omitempty"`

	Algorithms   []string      `yaml:"algorithms,omitempty"`     // defaults to ["RS256"]; every entry must be in allowedAlgorithms; always authoritative regardless of what a fetched key claims about itself (RFC 8725 §3.1)
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl,omitempty"` // defaults to defaultJWKSCacheTTL
	ClockSkew    time.Duration `yaml:"clock_skew,omitempty"`     // defaults to defaultClockSkew
}

// applyDefaults fills zero-value fields. Deliberately never inferred
// from fetched data (a JWKS document, IdP metadata): letting trust
// parameters be derived from the same remote data being verified
// reopens the classic JWT "algorithm confusion" vulnerability class. A
// missing default just means credentials are rejected (fails closed),
// not a silent downgrade.
func (j *JWTSource) applyDefaults() {
	if j.Name == "" {
		j.Name = j.Issuer
	}
	if j.JWKSCacheTTL == 0 {
		j.JWKSCacheTTL = defaultJWKSCacheTTL
	}
	if j.ClockSkew == 0 {
		j.ClockSkew = defaultClockSkew
	}
	if len(j.Algorithms) == 0 {
		j.Algorithms = []string{defaultAlgorithm}
	}
	if len(j.Credentials) == 0 {
		j.Credentials = []CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}}
	}
}

// validate checks a single JWTSource in isolation (no cross-source
// checks — those live in InboundAuthConfig.Validate). Assumes
// applyDefaults has already run, so Algorithms and Credentials are
// never empty here.
func (j *JWTSource) validate() error {
	if j.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}

	if j.JWKSURL == "" && j.OIDCDiscoveryURL == "" {
		return fmt.Errorf("one of jwks_url or oidc_discovery_url is required")
	}
	if j.JWKSURL != "" && j.OIDCDiscoveryURL != "" {
		return fmt.Errorf("jwks_url and oidc_discovery_url are mutually exclusive")
	}
	if j.JWKSURL != "" {
		if _, err := parseAbsoluteHTTPURL("jwks_url", j.JWKSURL); err != nil {
			return err
		}
	}
	if j.OIDCDiscoveryURL != "" {
		if _, err := parseAbsoluteHTTPURL("oidc_discovery_url", j.OIDCDiscoveryURL); err != nil {
			return err
		}
	}

	if j.CACert != "" {
		if _, err := ParseCACertPool(j.CACert); err != nil {
			return fmt.Errorf("ca_cert: %w", err)
		}
		// A CA bundle attached to an http:// endpoint is inert: no
		// handshake ever happens, so the trust requirement the operator
		// wrote down is silently not enforced. The checks above leave
		// exactly one of the two URLs set, so naming the offending field
		// is unambiguous.
		endpoint, field := j.JWKSURL, "jwks_url"
		if endpoint == "" {
			endpoint, field = j.OIDCDiscoveryURL, "oidc_discovery_url"
		}
		if strings.HasPrefix(strings.ToLower(endpoint), "http://") {
			return fmt.Errorf("ca_cert is set but %s is http://, so it would never be used; use https:// or remove ca_cert", field)
		}
	}

	for _, alg := range j.Algorithms {
		if !allowedAlgorithms[alg] {
			return fmt.Errorf("algorithms: %q is not a supported algorithm", alg)
		}
	}

	for i, c := range j.Credentials {
		if !allowedCredentialLocations[c.Location] {
			return fmt.Errorf("credentials[%d]: location %q must be one of header, cookie, query", i, c.Location)
		}
		if c.Name == "" {
			return fmt.Errorf("credentials[%d]: name is required", i)
		}
	}

	return nil
}

// SAMLSource describes the single, optional full interactive SAML SP
// integration this proxy supports: the IdP to redirect to, this proxy's
// own SP identity, where the IdP posts its response back, and how the
// resulting session is tracked. See InboundAuthConfig's doc comment for
// why this is a single optional value rather than a list like JWTSource.
type SAMLSource struct {
	// Name identifies this source in logs/errors and is what Validate
	// requires be unique across JWT+SAML — not Issuer. Optional: it
	// defaults to this source's own Issuer (see applyDefaults). See
	// JWTSource.Name for the full rationale, shared with this field.
	Name     string `yaml:"name,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty"`
	Issuer   string `yaml:"issuer"` // required — the IdP's entity ID; need not be unique (see Name)

	Audiences            []string      `yaml:"audiences,omitempty"`
	IDPMetadataURL       string        `yaml:"idp_metadata_url,omitempty"`        // required
	IDPMetadataCacheTTL  time.Duration `yaml:"idp_metadata_cache_ttl,omitempty"`  // defaults to defaultIDPMetadataCacheTTL
	SPBaseURL            string        `yaml:"sp_base_url,omitempty"`             // required — this proxy's own externally-reachable origin, e.g. "https://proxy.example.com"
	SPEntityID           string        `yaml:"sp_entity_id,omitempty"`            // required — this proxy's own identity to the IdP
	ACSPath              string        `yaml:"acs_path,omitempty"`                // required — where the IdP POSTs the SAMLResponse, relative to SPBaseURL
	SessionCookie        string        `yaml:"session_cookie,omitempty"`          // required
	SessionSigningKeyEnv string        `yaml:"session_signing_key_env,omitempty"` // required — NAME of an env var holding the signing key, never the key itself in YAML
	SessionDuration      time.Duration `yaml:"session_duration,omitempty"`        // defaults to defaultSessionDuration

	// SPKeyEnv/SPCert are optional and must be set together, or not at
	// all: an RSA keypair this proxy persists and advertises in its own
	// (samlsp-generated) SP metadata, enabling the IdP to encrypt
	// assertions to it. With neither set (the default), this proxy has
	// no persistent SP identity beyond its entity ID — see the README's
	// SAML section for exactly which IdP populations that excludes.
	// SPKeyEnv is the NAME of an env var holding a PEM-encoded RSA
	// private key (PKCS#1 or PKCS#8), never the key itself in YAML,
	// same convention as SessionSigningKeyEnv. SPCert is the matching
	// PEM-encoded X.509 certificate — public by nature, so it's fine
	// directly in YAML, unlike the key.
	SPKeyEnv string `yaml:"sp_key_env,omitempty"`
	SPCert   string `yaml:"sp_cert,omitempty"`
}

// applyDefaults fills zero-value fields.
func (s *SAMLSource) applyDefaults() {
	if s.Name == "" {
		s.Name = s.Issuer
	}
	if s.SessionDuration == 0 {
		s.SessionDuration = defaultSessionDuration
	}
	if s.IDPMetadataCacheTTL == 0 {
		s.IDPMetadataCacheTTL = defaultIDPMetadataCacheTTL
	}
}

// validate checks a single SAMLSource in isolation (no cross-source
// checks — those live in InboundAuthConfig.Validate).
func (s *SAMLSource) validate() error {
	if s.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if s.IDPMetadataURL == "" {
		return fmt.Errorf("idp_metadata_url is required")
	}
	if _, err := parseAbsoluteHTTPURL("idp_metadata_url", s.IDPMetadataURL); err != nil {
		return err
	}
	if s.SPBaseURL == "" {
		return fmt.Errorf("sp_base_url is required")
	}
	if _, err := parseAbsoluteHTTPURL("sp_base_url", s.SPBaseURL); err != nil {
		return err
	}
	if s.SPEntityID == "" {
		return fmt.Errorf("sp_entity_id is required")
	}
	if s.ACSPath == "" {
		return fmt.Errorf("acs_path is required")
	}
	if !strings.HasPrefix(s.ACSPath, "/") {
		return fmt.Errorf("acs_path must begin with %q", "/")
	}
	if s.ACSPath == "/healthz" {
		return fmt.Errorf("acs_path must not be %q: that path is always served unauthenticated and never reaches inbound.auth", "/healthz")
	}
	if s.SessionCookie == "" {
		return fmt.Errorf("session_cookie is required")
	}
	if s.SessionSigningKeyEnv == "" {
		return fmt.Errorf("session_signing_key_env is required")
	}
	v, ok := os.LookupEnv(s.SessionSigningKeyEnv)
	if !ok {
		return fmt.Errorf("session_signing_key_env: environment variable %q is not set", s.SessionSigningKeyEnv)
	}
	if len(v) < minSessionSigningKeyLen {
		return fmt.Errorf("session_signing_key_env: environment variable %q must be at least %d bytes, got %d",
			s.SessionSigningKeyEnv, minSessionSigningKeyLen, len(v))
	}

	if (s.SPKeyEnv == "") != (s.SPCert == "") {
		return fmt.Errorf("sp_key_env and sp_cert must be set together, or not at all")
	}
	if s.SPKeyEnv != "" {
		keyPEM, ok := os.LookupEnv(s.SPKeyEnv)
		if !ok {
			return fmt.Errorf("sp_key_env: environment variable %q is not set", s.SPKeyEnv)
		}
		key, err := ParseSPPrivateKey(keyPEM)
		if err != nil {
			return fmt.Errorf("sp_key_env: environment variable %q: %w", s.SPKeyEnv, err)
		}
		cert, err := ParseSPCertificate(s.SPCert)
		if err != nil {
			return fmt.Errorf("sp_cert: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("sp_cert: certificate's public key must be RSA to match sp_key_env, got %T", cert.PublicKey)
		}
		if !key.PublicKey.Equal(pub) {
			return fmt.Errorf("sp_cert: certificate's public key does not match sp_key_env's private key")
		}
	}

	return nil
}

// BasicSource describes the single, optional HTTP Basic authentication
// source: a fixed list of users, each with a bcrypt password hash, and
// the realm to advertise when challenging. See InboundAuthConfig's doc
// comment for why this is one optional value rather than a list, and
// why — unlike JWT and SAML, which identify themselves by Issuer — it
// has no identifying field at all.
//
// Passwords are stored only as bcrypt hashes, never plaintext — a
// plaintext value is rejected at load time by validate below, not
// quietly accepted and compared. The hash itself is not a secret (it
// can't be replayed as a credential), so it's fine directly in YAML;
// where an operator would still rather have it delivered by their
// secret-management path, ${env:...}/${file:...} references work here
// like they do in any other field (see interpolate.go).
type BasicSource struct {
	Disabled bool        `yaml:"disabled,omitempty"` // default false; the same "stage it without going live" switch JWT/SAML sources have
	Realm    string      `yaml:"realm,omitempty"`    // defaults to defaultBasicRealm; user-visible in a browser's login dialog
	Users    []BasicUser `yaml:"users"`              // required, at least one — a source that could never authenticate anyone is a config error, not a silent deny-all
}

// BasicUser is one username/bcrypt-hash pair in a BasicSource.
type BasicUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// applyDefaults fills zero-value fields.
func (b *BasicSource) applyDefaults() {
	if b.Realm == "" {
		b.Realm = defaultBasicRealm
	}
}

// validate checks a single BasicSource in isolation. Assumes
// applyDefaults has already run, so Realm is never empty here.
//
// Every password hash is parsed with bcrypt.Cost at load time rather
// than on the first request that presents a credential: it's what turns
// "someone pasted a plaintext password into the config" from a
// permanent, silent 401-for-everyone into an immediate startup failure
// naming the user — the same fail-closed-at-load-time philosophy as
// SAMLSource's session-key length check.
func (b *BasicSource) validate() error {
	if err := validateRealm(b.Realm); err != nil {
		return err
	}

	if len(b.Users) == 0 {
		return fmt.Errorf("users is required and must list at least one user")
	}

	seen := make(map[string]bool, len(b.Users))
	for i, u := range b.Users {
		if u.Username == "" {
			return fmt.Errorf("users[%d]: username is required", i)
		}
		if seen[u.Username] {
			return fmt.Errorf("users[%d]: username %q is already used by another user", i, u.Username)
		}
		seen[u.Username] = true

		if u.PasswordHash == "" {
			return fmt.Errorf("users[%d] (%q): password_hash is required", i, u.Username)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("users[%d] (%q): password_hash is not a bcrypt hash (generate one with `htpasswd -bnBC 12 \"\" 'password'`): %w", i, u.Username, err)
		}
	}

	return nil
}

// validateRealm rejects a realm that can't be expressed in the
// WWW-Authenticate challenge this proxy builds from it. Go's header
// writer would sanitize CR/LF on its own, and a quote would merely
// produce a malformed challenge rather than a header injection — but
// catching it at load time, where the operator can see it, beats
// shipping a subtly broken challenge that only some clients complain
// about.
func validateRealm(realm string) error {
	if realm == "" {
		return fmt.Errorf("realm must not be empty")
	}
	if strings.ContainsAny(realm, "\"\\") {
		return fmt.Errorf("realm %q must not contain a quote or backslash", realm)
	}
	for _, r := range realm {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("realm %q must not contain control characters", realm)
		}
	}
	return nil
}

// CredentialLocation is one place to look for a JWT source's bearer
// credential in an incoming request. A JWTSource's Credentials is a
// list of these, tried in order (e.g. header first, falling back to a
// cookie for browser-originated requests to the same issuer) — the
// first one that actually has a non-empty value at that location wins;
// "wins" here just means extraction succeeded, not that the value
// verifies. Only meaningful for JWTSource — a SAMLSource's "location"
// is its SessionCookie instead, set by the proxy's own ACS flow rather
// than looked up in an arbitrary request.
type CredentialLocation struct {
	Location string `yaml:"location"`         // "header" | "cookie" | "query"
	Name     string `yaml:"name"`             // header/cookie/query-param name, e.g. "Authorization"
	Prefix   string `yaml:"prefix,omitempty"` // stripped before parsing, e.g. "Bearer " — header-only in practice
}
