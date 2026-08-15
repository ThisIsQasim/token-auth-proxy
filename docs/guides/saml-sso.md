# Guide: SAML SSO

This guide walks through setting up the SAML Service Provider (SP)
integration end to end: what to configure, what to give your Identity
Provider (IdP), and what the login flow actually looks like. For the
exhaustive reference (every field, exact cookie/redirect behavior), see
the [main README's SAML section](../../README.md#saml-enforced).

Unlike the [JWT guide](jwt-authentication.md), this one isn't something
you can fully script end to end in a terminal — SAML login is
interactive and browser-driven. You'll need a real IdP (or an IdP your
org already runs) to test against: Okta, Entra ID/Azure AD, Google
Workspace, Keycloak, and Shibboleth all work.

## How it works, briefly

This is a full interactive SP integration, not just signature checking:
an unauthenticated request gets redirected (`302`) to your IdP's SSO
URL; the IdP redirects the browser back to the proxy's ACS (Assertion
Consumer Service) endpoint with a signed SAML assertion; the proxy
verifies it, issues a signed session cookie, and redirects the browser
to the URL it originally asked for. Every later request just needs that
cookie — no re-redirect until the session expires.

## Step 1: Decide your SP identity

Three values, all yours to choose (not given to you by the IdP):

- **`sp_base_url`** — this proxy's own externally-reachable origin,
  e.g. `https://proxy.example.com`. **Must be `https://`** for real use
  — the ACS callback is cross-site, so the tracking cookie needs
  `SameSite=None`, which browsers only honor on `Secure` cookies.
  `http://` works for local dev/test only (the proxy warns at startup
  if it isn't https).
- **`sp_entity_id`** — this SP's identifier, conventionally
  `<sp_base_url>/saml/metadata` even though this proxy doesn't serve a
  metadata endpoint at that path (most IdPs are configured with SP
  details manually or via a metadata *file*, not a live fetch).
- **`acs_path`** — where the IdP POSTs the assertion back to, e.g.
  `/saml/corp-sso/acs`. Combined with `sp_base_url`, this is the full
  ACS URL you'll give the IdP.

## Step 2: Generate a session-signing key

The session cookie is HS256-signed with a secret you provide via an
**environment variable name** (never the secret itself in YAML):

```sh
openssl rand -base64 32
```

Export the result somewhere the proxy process can read it — e.g.
`export CORP_SSO_SESSION_KEY=<output>` — and reference the *name* of
that variable in config (`session_signing_key_env: "CORP_SSO_SESSION_KEY"`).
It must be at least 32 bytes; the proxy refuses to start otherwise.

## Step 3: Configure the SAML source

```yaml
inbound:
  auth:
    saml:
      name: corp-sso
      issuer: "https://idp.corp.example.com/metadata"    # the IdP's entity ID
      idp_metadata_url: "https://idp.corp.example.com/metadata"
      sp_base_url: "https://proxy.example.com"
      sp_entity_id: "https://proxy.example.com/saml/metadata"
      acs_path: "/saml/corp-sso/acs"
      session_cookie: "corp_sso_session"
      session_signing_key_env: "CORP_SSO_SESSION_KEY"
      session_duration: 8h        # optional, default 12h
      idp_metadata_cache_ttl: 1h  # optional, default shown
```

`issuer` must exactly match the `entityID` your IdP's own metadata
advertises — the proxy cross-checks this the same way the JWT leg
checks a token's `iss`.

## Step 4: Register the SP with your IdP

Give your IdP administrator (or configure yourself, if it's
self-service):

- **ACS URL**: `<sp_base_url><acs_path>`, e.g.
  `https://proxy.example.com/saml/corp-sso/acs`
- **SP Entity ID**: your configured `sp_entity_id`
- **Binding**: HTTP-POST for the ACS endpoint

Most IdPs want this as an SP metadata XML file rather than filled-in
fields one at a time — this proxy doesn't serve one itself (see
Limitations below), so you'll typically hand-write or generate one from
these same three values, or use whatever your IdP's admin console
offers for manual SP registration.

## Step 5: Try the login flow

1. Reload config (or start the proxy) with the SAML source above.
2. Visit any URL served by the proxy in a browser — you'll land on your
   IdP's login page instead.
3. Log in. The IdP redirects your browser back to the ACS URL; the
   proxy verifies the assertion, sets `corp_sso_session`, and redirects
   you to the page you originally asked for.
4. Subsequent requests just carry the cookie — no more redirects until
   `session_duration` elapses, or the cookie is cleared.

A missing, tampered, or expired session redirects back to the IdP
exactly like a fresh unauthenticated request — you'll never see a raw
`401` from the SAML leg, only a login prompt.

## Encrypted assertions (optional)

Some IdPs — Shibboleth by default, and IdPs joined to the
InCommon/eduGAIN research-and-education federations, per that
federation's membership profile — send `EncryptedAssertion` elements
instead of plaintext ones. Commercial SaaS IdPs (Okta, Entra ID, ...)
don't require this by default. If yours does, generate a persistent
keypair:

```sh
openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem -out sp-cert.pem \
  -days 825 -nodes -subj "/CN=proxy.example.com"
```

`sp-key.pem` goes behind an env var (same convention as the session
key — never the key itself in YAML); `sp-cert.pem` is public and can go
directly in config:

```sh
export CORP_SSO_SP_KEY="$(cat sp-key.pem)"
```

```yaml
      sp_key_env: "CORP_SSO_SP_KEY"
      sp_cert: |
        -----BEGIN CERTIFICATE-----
        ...contents of sp-cert.pem...
        -----END CERTIFICATE-----
```

Both fields must be set together or not at all. Once set, the proxy
advertises the certificate as an encryption key in its own SP metadata
and transparently decrypts `EncryptedAssertion`s on the ACS callback —
give your IdP admin `sp-cert.pem` (or the equivalent metadata) so they
know to encrypt for it.

This does **not** enable signed `AuthnRequest`s — a separate,
still-unimplemented capability. An IdP that specifically requires
signed `AuthnRequest`s (`WantAuthnRequestsSigned` in its metadata) won't
accept requests from this proxy regardless of whether a keypair is
configured.

## Combining SAML with JWT

Both can be configured and enabled at once. Per request: the ACS path
is always routed to SAML first; then, if a JWT-shaped credential was
actually presented, JWT alone decides (a bad bearer token never falls
back to a SAML redirect); only a genuinely credential-less request gets
SAML's redirect-or-forward treatment. This is useful for a backend that
serves both browser users (SAML) and API/service clients (JWT) on the
same route.

## Production checklist

- `sp_base_url` is `https://`, not `http://`.
- `session_signing_key_env` points at a real, ≥32-byte secret, set in
  the actual runtime environment (not committed anywhere).
- `idp_metadata_url` is reachable from wherever the proxy runs — a
  refresh failure keeps serving the last-known-good metadata, but the
  *first* fetch has nothing to fall back to.
- If your IdP encrypts assertions, `sp_key_env`/`sp_cert` are set and
  the certificate has been shared with the IdP.

## Not implemented

Single Logout, IdP-initiated login, an SP metadata HTTP endpoint, and
content-negotiated 401-vs-redirect are all deliberately out of scope
for now — see the [README's SAML section](../../README.md#saml-enforced)
for the reasoning behind each.
