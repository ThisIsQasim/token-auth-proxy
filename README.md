# token-auth-proxy

A minimal HTTP reverse proxy built on Go's standard library (`net/http` /
`net/http/httputil`). It forwards every request to a single backend
target, configured via a YAML file (with hot-reload), CLI flags, and/or
environment variables. It can check inbound HTTP Basic credentials,
verify JWT bearer tokens, and/or enforce an interactive SAML SP or OIDC
browser login
before forwarding (see [Auth](#auth) below), and restrict which
authenticated identities may use which methods and paths (see
[Authorization (ACLs)](#authorization-acls)). There's still no per-path
routing: every allowed request goes to the same `target`.

📖 **New here?** This README is the exhaustive technical reference. For
an introduction, example use cases, a getting-started walkthrough, and
task-oriented guides (Basic, JWT, SAML, OIDC login, hot-reload, observability), see
**[the docs](./docs/README.md)**.

## How it works

- Config comes from up to three layers, in this precedence — **flag >
  env > file > built-in default**:
  - `--config`/`TAP_CONFIG` points at a YAML file. When set, the proxy
    watches that file's parent directory for changes (covers plain
    in-place writes, atomic rename-based saves, and Kubernetes ConfigMap
    volume symlink-swaps alike) and debounces bursts of filesystem
    events into a single reload.
  - Every other flag/env var (see [Configuration](#configuration) below)
    is re-applied on top of the file on *every* load, including every
    hot-reload — so e.g. a `--target` flag keeps winning even if the
    file changes `target` underneath it, while fields you didn't
    override still hot-reload normally from the file.
  - If `--config`/`TAP_CONFIG` isn't set at all, the proxy runs with a
    static configuration built entirely from flags/env — no file, no
    watch, no hot-reload.
- `listen_addr` and `timeouts` are the only fields that *don't*
  hot-reload: they're read once, when the listener/transport are built
  at startup, so a later file change to those is logged as requiring a
  restart, not silently ignored. Everything else hot-reloads at
  runtime: `target`, `inbound.auth` (the trusted Basic/JWT/SAML
  sources and the login page, see [Auth](#auth) below) and `acl`.
- A malformed or invalid config write is logged and discarded — the
  previously loaded config stays live, so a transient bad write never
  takes the proxy down.
- The backend target swaps atomically: a request already in flight when
  the target changes always completes against the backend it started
  with.

## Configuration

Every field is settable via a flag, an environment variable (`TAP_`
prefixed), or a YAML file field — see [`config.example.yaml`](./config.example.yaml)
for the file form:

| Flag | Env var | YAML key | Default |
|---|---|---|---|
| `--config` | `TAP_CONFIG` | *(n/a — this selects the file itself)* | — |
| `--target` | `TAP_TARGET` | `target` | *(required if `--config` isn't set)* |
| `--listen-addr` | `TAP_LISTEN_ADDR` | `listen_addr` | `:8080` |
| `--timeout-read-header` | `TAP_TIMEOUT_READ_HEADER` | `timeouts.read_header` | `5s` |
| `--timeout-read` | `TAP_TIMEOUT_READ` | `timeouts.read` | `30s` |
| `--timeout-write` | `TAP_TIMEOUT_WRITE` | `timeouts.write` | `30s` |
| `--timeout-idle` | `TAP_TIMEOUT_IDLE` | `timeouts.idle` | `120s` |
| `--timeout-dial` | `TAP_TIMEOUT_DIAL` | `timeouts.dial` | `5s` |
| `--timeout-response-header` | `TAP_TIMEOUT_RESPONSE_HEADER` | `timeouts.response_header` | `15s` |
| `--inbound-auth-jwt-json` | `TAP_INBOUND_AUTH_JWT_JSON` | `inbound.auth.jwt` | *(none — file's list, if any, passes through)* |
| `--inbound-auth-saml-json` | `TAP_INBOUND_AUTH_SAML_JSON` | `inbound.auth.saml` | *(none — file's source, if any, passes through)* |
| `--inbound-auth-basic-json` | `TAP_INBOUND_AUTH_BASIC_JSON` | `inbound.auth.basic` | *(none — file's source, if any, passes through)* |
| `--inbound-auth-login-page-json` | `TAP_INBOUND_AUTH_LOGIN_PAGE_JSON` | `inbound.auth.login_page` | *(none, file's value, if any, passes through)* |
| `--inbound-oauth-server-json` | `TAP_INBOUND_OAUTH_SERVER_JSON` | `inbound.oauth_server` | *(none; the file's block, if any, passes through)* |
| `--outbound-token-json` | `TAP_OUTBOUND_TOKEN_JSON` | `outbound.token` | *(none; the file's block, if any, passes through)* |
| `--acl-json` | `TAP_ACL_JSON` | `acl` | *(none; the file's rules, if any, pass through)* |

A no-file, flags-only run, for example:

```sh
token-auth-proxy --target http://localhost:9000 --listen-addr :8080
```

`GET /healthz` always returns `200 OK` without touching the backend —
mount it as a Kubernetes liveness/readiness probe.

### Value references (`${env:...}` / `${file:...}`)

Any string value **in the config file** can pull its content in from
somewhere else, resolved after the YAML is parsed and before it's
validated:

```yaml
target: "${env:BACKEND_URL}"
inbound:
  auth:
    basic:
      users:
        - username: alice
          password_hash: "${file:/run/secrets/alice.bcrypt}"
```

- **`${env:NAME}`** — the environment variable `NAME`. An unset
  variable is an error: the load fails rather than silently
  substituting an empty value. A variable that's set but empty resolves
  to `""`.
- **`${file:/path}`** — the file's contents, with exactly one trailing
  newline stripped so `echo secret > f` and `printf secret > f` behave
  the same. A relative path resolves against **the config file's own
  directory**, not the process's working directory. Files over 1 MiB
  are rejected.
- Both forms can appear mid-string and more than once:
  `"https://${env:IDP_HOST}/metadata"`.
- **`$` is only special immediately before `{`.** Everything else —
  including a bcrypt hash like `$2y$12$...`, the one value in this
  schema guaranteed to contain `$` — passes through byte-for-byte with
  no escaping. Write `$${` if you need a literal `${`.
- A `${...}` that isn't a reference (`${HOME}`, `${C:\path}`) is left
  exactly as written. A reference naming a type that doesn't exist
  (`${vault:x}`) is an error rather than a passthrough, since that's a
  typo in something clearly meant as a reference.
- Errors name the config key that failed, and a failure during a
  *reload* keeps the previously loaded config live, exactly like a
  malformed file does.
- **Only the config file is interpolated.** Flags, `TAP_` environment
  variables and the `TAP_*_JSON` blobs are taken literally — they're
  already coming from the environment.
- **Referenced files aren't watched.** The watcher watches the config
  file's directory only, so rotating a `${file:...}` secret takes
  effect on the next config reload or restart.

The existing `session_signing_key_env` / `sp_key_env` fields, which
name an environment *variable* rather than holding a value, are
unchanged and keep working.

## Auth

`inbound`/`outbound` are top-level config sections, siblings of
`target`/`listen_addr`/`timeouts`. `inbound.auth.jwt` (a **list**),
`inbound.auth.saml` (**at most one** source, not a list — no per-path
routing exists to pick among multiple IdPs by) and `inbound.auth.basic`
(**at most one** source, for its own reason — a challenge names exactly
one realm, and two user lists guarding one backend is one user list)
describe trusted credential sources. `inbound.oauth_server` and
`outbound.token`, which go together, turn the proxy into an OAuth server
that issues tokens the backend trusts (documented under "OAuth server"
once it ships); the rest of `outbound` is reserved for a later pass
(rewriting credentials on the backend leg, e.g. verifying an inbound SAML
assertion and minting an outbound OIDC-style JWT). See
[`config.example.yaml`](./config.example.yaml) for a full commented-out
example of each.

**There is no separate `enabled` switch** for any of them — a source
counts as active unless it's `disabled: true`; the same field also lets
you pull one JWT source out of rotation, or stage a source without
going live, without touching the rest. Both `target` and `inbound.auth`
hot-reload together when `--config`/`TAP_CONFIG` is set — add, remove,
edit, or (re-)enable a source and it takes effect on the next request,
no restart.

### JWT (enforced)

A request matching a configured, non-disabled JWT source's `issuer`
must carry a valid token or the proxy responds `401` before the request
reaches the backend. With zero non-disabled JWT sources configured,
nothing is enforced and every request passes through unchanged — unless
a SAML source is also configured and enabled, in which case SAML takes
over; see below for how the two combine.

- **Credential extraction**: `credentials` is a list of places to look
  for the token (`header`/`cookie`/`query`, each with an optional
  prefix like `"Bearer "`), tried in order, first successful extraction
  wins — it defaults to the `Authorization` header if omitted.
- **Routing**: the token's own (unverified) `iss` claim selects which
  configured source's keys and policy to verify under — never any other
  unverified field. Usually one source per issuer, but more than one
  is allowed (e.g. rolling a JWKS/CA migration): they're tried in the
  order they're listed, and the first to fully verify the token wins.
  Each source is identified by `name`, which defaults to its own
  `issuer` and only needs setting explicitly once two sources share
  one.
- **Key material**: a `jwks_url` or `oidc_discovery_url` (exactly one).
  An OIDC discovery document's `jwks_uri` is resolved once and then
  treated exactly like a directly configured `jwks_url`; the
  document's `issuer` must match the source's configured `issuer`, and
  its advertised signing algorithms are never consulted.
- **TLS trust for those endpoints**: `ca_cert`, an optional PEM CA
  bundle (or that same PEM, base64-encoded — handy for pasting inline
  into `--inbound-auth-jwt-json`/`TAP_INBOUND_AUTH_JWT_JSON`, which
  have no `${file:...}` support and no YAML block-scalar syntax to
  carry raw PEM's newlines) used to verify the certificate presented by
  `jwks_url` / `oidc_discovery_url` (and the `jwks_uri` a discovery
  document resolves to). It **replaces** the system trust store for
  this source rather than adding to it, so pinning the wrong bundle
  fails the fetch instead of quietly falling back to public trust. It
  covers key material only — the backend and the SAML IdP metadata
  fetch are unaffected (a SAML source has its own `ca_cert`). Write `ca_cert: "${file:/path/to/ca.crt}"`
  ([value references](#value-references-env--file)) to load it from a
  mounted file; a rotated CA takes effect on the next reload. Setting it
  on an `http://` endpoint is a config error, since it would never be
  used. An invalid `ca_cert` (bad PEM, bad base64, or content that
  isn't a certificate) fails the config load.
- **Verification**: signature under one of `algorithms` (defaults to
  `["RS256"]` — this list is always authoritative, never the token's own
  `alg` header or anything a JWKS/discovery document claims about
  itself, per [RFC 8725 §3.1](https://www.rfc-editor.org/rfc/rfc8725#section-3.1)),
  `exp` (required — a token with no expiration is always rejected) and
  `nbf` within `clock_skew` leeway, `aud` against `audiences` (any-of,
  unrestricted if omitted), and `iss` matching exactly.
- **On rejection**: `401` with a `WWW-Authenticate: Bearer` header (or
  `Bearer error="invalid_token"` if a credential was present but
  invalid) and a minimal plaintext body — the specific reason
  (expired, wrong issuer, bad signature, ...) is never included in the
  response, only in the proxy's own structured logs.
- **When the keys can't be fetched**: `503` with `Retry-After` (30 seconds, the
  resolver's retry window) and no `WWW-Authenticate`, logged as
  `keys_unavailable` at warn level. The token was never judged, so this is
  not a `401 invalid_token`.
- **Limitation**: a `query`-location credential is forwarded to the
  backend as part of the URL, which [RFC 6750 §2.3](https://www.rfc-editor.org/rfc/rfc6750#section-2.3)
  discourages (it can end up in access logs, `Referer` headers, browser
  history) — prefer `header` or `cookie` where the client supports it.

`inbound.auth.jwt` is also settable via
`--inbound-auth-jwt-json`/`TAP_INBOUND_AUTH_JWT_JSON`, a **JSON array**
fully replacing the list (not merged with the file's value), using the
same snake_case field names as YAML:

```sh
TAP_INBOUND_AUTH_JWT_JSON='[{"name":"internal-k8s","issuer":"https://kubernetes.default.svc","jwks_url":"https://kubernetes.default.svc/openid/v1/jwks"}]'
```

The value is always inline JSON, never a file path — for a larger or
more complex source list, use `--config`/`TAP_CONFIG` instead. Like
every other override, a flag wins over its env var, and (when
`--config` is also set) it's re-applied on every hot-reload, so it keeps
winning over whatever the file says for that field. Duration fields
inside the JSON (`jwks_cache_ttl`, ...) should be written as strings
(`"10m"`), the same as in YAML.

### Browser login with OIDC

A JWT source whose issuer is an OpenID Provider can also sign browsers
in. Add a `login` block to the source (the source needs
`oidc_discovery_url`, since the authorization and token endpoints come
from the discovery document):

```yaml
inbound:
  auth:
    jwt:
      - issuer: https://idp.example.com/application/o/proxy/
        oidc_discovery_url: https://idp.example.com/application/o/proxy/.well-known/openid-configuration
        login:
          client_id: my-proxy
          client_secret: ${env:PROXY_OIDC_CLIENT_SECRET}   # omit for a public client
          sp_base_url: https://proxy.example.com
```

**`login` fields** (all per source):

| Field | Default | Meaning |
|---|---|---|
| `client_id` | required | OAuth client ID; also the default `audiences` (if you set `audiences` it must include it) |
| `client_secret` | none | Makes it a confidential client. Use `${env:NAME}` or `${file:PATH}`. Omit for a public client |
| `token_auth_method` | `client_secret_basic` | `client_secret_basic` or `client_secret_post`; only with a secret |
| `sp_base_url` | required | The proxy's own origin as the browser sees it |
| `callback_path` | `/_tap/oidc/callback` | Register `sp_base_url + callback_path` as the redirect URI |
| `scopes` | `openid profile email` | Requested scopes; must include `openid` |
| `cookie_name` | `tap_id_token` | The ID token cookie; letters, digits and `!#$%&'*+-.^_`|~` only, and not starting with `tap_login_` |
| `label` | the source name | Button text on the login picker |
| `refresh` | `false` | Renew the session with a refresh token (see below) |
| `refresh_max_age` | `720h` | Lifetime of the refresh cookie; only with `refresh` |
| `end_session` | `false` | Make `/_tap/logout` also end the session at the identity provider (see [Logging out](#logging-out)) |
| `post_logout_redirect_uri` | none | Where the provider sends the browser afterwards; must be registered with it; only with `end_session` |

- **Confidential or public.** With `client_secret` (write it as `${env:NAME}` or `${file:PATH}`,
  not inline) the proxy authenticates to the token
  endpoint with the secret, via `token_auth_method`
  (`client_secret_basic`, the default, or `client_secret_post`).
  Without it the proxy is a public client and relies on PKCE alone. PKCE
  (S256) is used in both cases.
- **Flow.** A credential-less browser navigation (`GET`/`HEAD` accepting
  `text/html`) is redirected to the IdP with `state`, `nonce` and a PKCE
  challenge. The callback (`callback_path`, default `/_tap/oidc/callback`,
  relative to `sp_base_url`; register `sp_base_url + callback_path` as
  the redirect URI) checks `state`, exchanges the code, verifies the ID
  token and its `nonce`, and stores the ID token in a cookie
  (`cookie_name`, default `tap_id_token`), then returns the browser to
  the page it asked for.
- **Scopes and claims.** `login.scopes` (default `openid profile email`)
  decides which claims the ID token carries, and ACL `claims` can only
  match what is in it. Many IdPs only include `groups` (or similar) when
  that scope is requested, so add it, e.g. `scopes: [openid, profile, email, groups]`.
  `openid` is required.
- **No separate session.** The login cookie is added to the source's
  `credentials`, so every later request is verified by the ordinary JWT
  leg and ACLs use `mode: jwt` with `source` and `claims` as for any
  bearer token. The session therefore lasts as long as the ID token (unless
  refresh is on, below); the token must also fit in a cookie (about 4KB).
  `audiences` defaults to the `client_id`; if you set it, it must contain
  the `client_id`.
- **Logging out.** <a id="logging-out"></a>`/_tap/logout` (GET, HEAD or POST) clears the SAML session cookie, every login source's ID token and refresh cookies, and the remembered sign-in choice, then redirects to `return_to` (a same-origin path, default `/`, which lands on the sign-in page). It is served by the proxy and skips ACLs, like the other `/_tap/` routes, and is only available when SAML or a login source is configured. Clearing cookies forgets the session here only: if the identity provider's own session is still alive, signing in again is instant. Set `login.end_session: true` and the redirect goes to the provider's `end_session_endpoint` (from its discovery document) with the ID token as `id_token_hint`, ending that session too; add `post_logout_redirect_uri` to bring the browser back, after registering it with the provider. A provider that advertises no `end_session_endpoint` gets the local logout. Basic credentials are held by the browser itself, so no response can clear them, and SAML single logout is not supported.
- **Refresh tokens.** Set `login.refresh: true` to keep a browser signed in
  past the ID token's expiry. The refresh token is stored in a second
  cookie (`<cookie_name>_refresh`, lasting `refresh_max_age`, default
  30 days) and never forwarded to the backend. When a request arrives
  with that cookie but no ID token, the proxy redeems it, sets fresh
  cookies, and the request carries on as if the session had not expired,
  for browser and API requests alike. The IdP has to issue refresh
  tokens to this client, which usually means adding `offline_access` to
  `scopes` yourself (it is not added for you, since some IdPs reject
  it); a warning is logged at login if none is issued. If the IdP
  refuses the token (revoked, expired) the cookie is cleared and a
  browser goes through a full login; if the IdP is unreachable the
  request gets a `503` and the cookie is kept. A login cookie that
  fails verification (the browser's clock is behind and the token has
  expired by the proxy's, or the IdP rotated its signing key) is treated
  as an expired session: it is dropped and renewed the same way, or the
  browser goes through login again. A token sent in a header is never
  treated like this; it is a plain `401`. Parallel requests share
  one redemption (for 30 seconds per refresh token, per process), so a
  rotating IdP sees each token once; behind several replicas without
  sticky routing a rotating IdP can still see a reuse.
- **Other clients.** Requests that are not browser navigations still get
  the plain `401`. Bearer tokens in the `Authorization` header keep
  working on the same source.
- **More than one source.** Each source with a `login` block is a
  separate login method with its own client, scopes and cookies, and
  gets its own button on the picker. Their `callback_path` and
  `cookie_name` values must differ (validation rejects duplicates):

  ```yaml
  inbound:
    auth:
      jwt:
        - name: authentik
          issuer: https://auth.example.com/application/o/proxy/
          oidc_discovery_url: https://auth.example.com/application/o/proxy/.well-known/openid-configuration
          login:
            client_id: proxy-a
            client_secret: ${env:AUTHENTIK_SECRET}
            sp_base_url: https://proxy.example.com
            scopes: [openid, profile, email, groups]
        - name: google
          issuer: https://accounts.google.com
          oidc_discovery_url: https://accounts.google.com/.well-known/openid-configuration
          login:
            client_id: proxy-b
            sp_base_url: https://proxy.example.com
            callback_path: /_tap/oidc/google/callback
            cookie_name: tap_id_token_google
            scopes: [openid, email]
  ```

- **Several methods, one picker.** When more than one interactive method
  is configured (SAML, Basic, and each JWT source with `login`), a
  credential-less browser navigation is redirected to `/_tap/login`, a
  page with one button per method (`login.label` names a JWT source's
  button, defaulting to the source name). Choosing Basic answers with a
  `401` challenge so the browser shows its password prompt; choosing
  SAML or OIDC starts that flow. The choice is remembered in a
  `tap_login_method` cookie so the picker is skipped next time. With a
  single method there is no picker. The `/_tap/login` paths and the default
  callback (`/_tap/oidc/callback`) are served by the proxy and never reach
  the backend; keep `/_tap/` out of your backend routes.
- **Styling the picker.** `inbound.auth.login_page.css` is appended
  after the built-in styles. Override the custom properties `--bg`,
  `--fg`, `--card`, `--line`, `--accent` and `--accent-fg`, or target
  the classes `tap-login` (the card), `tap-login-title` and
  `tap-login-method` (each button). `${file:/path/to.css}` keeps the
  stylesheet in its own file. It may not contain `</style`.

### Basic (enforced)

`inbound.auth.basic` is a fixed list of users with bcrypt password
hashes. With it configured and not disabled, a request must present a
matching `Authorization: Basic` credential or it never reaches the
backend.

```yaml
inbound:
  auth:
    basic:
      realm: "internal tools"      # optional, defaults to "restricted"
      users:
        - username: alice
          password_hash: "$2y$12$..."
        - username: bob
          password_hash: "${file:/run/secrets/bob.bcrypt}"
```

- **bcrypt only.** `password_hash` must be a bcrypt hash; a plaintext
  password is rejected at config-load time, naming the user, rather
  than silently rejecting every login afterwards. Generate one with
  `htpasswd -bnBC 12 "" 'password' | tr -d ':\n'`. A hash is a
  verifier, not a credential, so it's fine directly in the config file;
  `${file:...}`/`${env:...}` ([above](#value-references-env--file))
  work here too.
- **`realm`** is what a browser shows in its login dialog and what
  clients scope a saved password to. Quotes, backslashes and control
  characters are rejected at load time.
- **On rejection**: `401` with
  `WWW-Authenticate: Basic realm="...", charset="UTF-8"` and a minimal
  plaintext body. An unknown username and a wrong password are answered
  identically, log the same `bad_credential` reason, and take the same
  time to answer — there's no way to tell from the outside which of the
  two happened.
- **Verified credentials are cached for 5 minutes**, since bcrypt costs
  tens to hundreds of milliseconds by design and a Basic credential is
  re-presented on every request. This is not a revocation window: any
  change to the basic source drops the cache, so removing a user takes
  effect immediately.
- **Under sustained load, verification can shed requests.** Concurrent
  bcrypt comparisons are capped; past a 5-second wait a request gets
  `503` with `Retry-After` and logs `basic_saturated`, rather than a
  `401` that would wrongly blame the credential.
- The `Authorization` header is **forwarded to the backend unchanged**,
  like every other leg.
- **Limitation**: browsers don't send `Authorization` on a CORS
  preflight `OPTIONS`, so preflights get a `401` — already true of the
  JWT leg.

`inbound.auth.basic` is also settable via
`--inbound-auth-basic-json`/`TAP_INBOUND_AUTH_BASIC_JSON`, a **JSON
object** fully replacing the source, following the same
precedence/hot-reload rules as the JWT and SAML overrides:

```sh
TAP_INBOUND_AUTH_BASIC_JSON='{"realm":"internal","users":[{"username":"alice","password_hash":"$2y$12$..."}]}'
```

Note this path is **not** interpolated (it's already an environment
value), so `${file:...}` inside the JSON stays literal text.

### SAML (enforced)

The SAML source is a full interactive SP integration: SP-initiated
redirect to the IdP, ACS callback, session cookie — all hot-reloadable.
A persistent SP keypair (`sp_key_env`/`sp_cert`) is optional: without
it, this proxy has no SP identity beyond its entity ID, which is fine
for most SaaS IdPs; with it, the IdP can send (and this proxy will
transparently decrypt) `EncryptedAssertion` elements — see the
limitation below for exactly who that does and doesn't unblock.

- **Unauthenticated request**: redirected (`302`) to the IdP's SSO URL
  with a short-lived, HS256-signed tracking cookie (`saml_`-prefixed)
  recording the original URL and the expected SAML request ID.
- **ACS callback** (`acs_path`, default `/_tap/saml/acs`): the IdP's `POST`ed assertion is
  signature-verified against `idp_metadata_url` (cross-checked that its
  `entityID` matches `issuer` — the SAML analogue of the JWT leg's
  issuer check), then a session cookie (`session_cookie`) is issued and
  the browser is redirected back to the URL it originally requested.
- **Session cookie**: HS256-signed with the secret named by
  `session_signing_key_env` (an env var *name*, never the key itself in
  YAML; that env var's value must be **at least 32 bytes**), valid for
  `session_duration` (default 12h). A missing, tampered, or expired
  session redirects back to the IdP exactly like a fresh unauthenticated
  request — never a `401`.
- **IdP metadata**: fetched from `idp_metadata_url` and cached for
  `idp_metadata_cache_ttl` (default 1h), or until the earliest signing
  certificate in it expires if that comes sooner (never refetched more
  than once a minute, so an IdP that still publishes an expired
  certificate isn't hammered); a refresh failure keeps serving
  the last-known-good metadata rather than logging every active session
  out, but the *first* fetch (nothing cached yet) fails closed — there's
  no sensible degraded behavior without at least one working fetch. A
  failed refresh is retried after 5 minutes (or the TTL, if shorter). An
  ACS callback that fails validation triggers one extra fetch and a
  second try with the fresh metadata, at most once a minute, so an IdP
  that rotated its signing key doesn't lock users out until the cache
  expires.
- **`ca_cert`** (optional): a PEM CA bundle (or that same PEM,
  base64-encoded) used to verify the TLS certificate of
  `idp_metadata_url`, for an IdP behind a private CA. Like the JWT
  source's, it **replaces** the system trust store for that fetch rather
  than adding to it, and it covers the metadata fetch only: the
  browser talks to the IdP's SSO endpoint directly. Write
  `ca_cert: "${file:/path/to/ca.crt}"` to load it from a mounted file.
  An invalid bundle, or one set on an `http://` metadata URL, fails the
  config load.
- **`sp_base_url`** (required): this proxy's own externally-reachable
  origin, e.g. `https://proxy.example.com` — used to build the ACS URL
  advertised to the IdP. **Must be `https://` in any real deployment**:
  the IdP's ACS `POST` is cross-site, so the tracking cookie needs
  `SameSite=None`, which browsers only honor on `Secure` (https)
  cookies. `http://` is accepted (and warned about at startup) purely
  for local dev/test, where the IdP is reachable over plain HTTP too.
- **`sp_key_env`/`sp_cert`** (optional, must be set together or not at
  all): an RSA keypair this proxy persists and advertises as an
  encryption key in its own SP metadata. `sp_key_env` is an env var
  *name* holding a PEM-encoded RSA private key (PKCS#1 or PKCS#8),
  never the key itself in YAML — same convention as
  `session_signing_key_env`. `sp_cert` is the matching PEM-encoded
  X.509 certificate; being public, it's fine directly in YAML. When
  set, an IdP that encrypts assertions (rather than sending them
  plaintext) is decrypted transparently on the ACS callback — this
  does **not** enable signed `AuthnRequest`s, a separate, still
  unimplemented capability (see the limitation below).

`inbound.auth.saml` is also settable via
`--inbound-auth-saml-json`/`TAP_INBOUND_AUTH_SAML_JSON`, a
**JSON object** (not an array) fully replacing the source, following
the same precedence/hot-reload rules as the JWT override above.

**When more than one mode is configured and enabled**, per request, in
order:

1. The **ACS path** is always dispatched to SAML first, regardless of
   anything else.
2. If an `Authorization: Basic` credential was presented, **basic alone
   decides** — a bad password gets `401`, never a SAML redirect and
   never a JWT check. Basic is ahead of JWT deliberately: a JWT source
   configured to read the `Authorization` header with no `prefix` would
   otherwise swallow a Basic credential and reject it as a malformed
   token. (That exact pairing is rejected at config-load time, so this
   ordering is a second line of defense rather than the only one.) The
   consequence to know: a client sending a Basic header *and* a JWT in
   a cookie or query parameter is judged on the Basic credential alone.
3. Otherwise, if a **JWT**-shaped credential was actually presented
   (any configured `credentials` location had a non-empty value), JWT
   alone decides — a bad bearer token gets `401`, never a SAML
   redirect.
4. Otherwise a credential-less request is handled as a browser login,
   depending on how many interactive methods (SAML, Basic, and JWT
   sources with `login`) are configured. With two or more, a browser
   navigation goes to the method it chose before, or to the login picker
   (see "Browser login with OIDC"). With exactly one: **SAML** makes the
   redirect-or-forward decision; a JWT source with `login` redirects a
   browser navigation to the IdP. Note this comes *before* step 5, so
   with SAML enabled a credential-less request is redirected to the IdP
   and never sees a Basic challenge, unless the picker is in play and
   Basic was chosen. Callbacks (SAML ACS, OIDC) and `/_tap/login` are
   dispatched ahead of step 2.
5. Otherwise the `401` carries a challenge for **each** enabled mode
   (`Basic realm="..."` and/or `Bearer`), as separate
   `WWW-Authenticate` header lines.

A request that's neither a JWT-only nor a SAML-only shape (e.g. a JSON
API client with no way to display an IdP login page) has no special
handling — see the content-negotiation gap below.

**Not implemented, deliberately out of scope for now:**

- **Signed `AuthnRequest`s.** `sp_key_env`/`sp_cert` (above) enable
  decrypting `EncryptedAssertion` elements, but never turn on
  `SignRequest` — the two are independent capabilities in the
  underlying SAML library, and this proxy never signs its own
  `AuthnRequest`s regardless of whether a keypair is configured. An IdP
  that specifically requires signed `AuthnRequest`s (`WantAuthnRequestsSigned`
  in its metadata) won't accept requests from this proxy. Commercial
  SaaS IdPs (Okta, Entra ID, and similar) don't require this by
  default; some individual Shibboleth deployments opt into requiring it
  per-SP, though it isn't the InCommon/eduGAIN federation-wide default
  the way encrypted assertions are.
- **Single Logout** and **IdP-initiated login** — no SLO URL field, and
  IdP-initiated login is never accepted (accepting it would require
  disabling the `InResponseTo` replay check entirely).
- **Content negotiation on the redirect-vs-401 decision.** A
  credential-less request always gets SAML's `302` when SAML is
  enabled, even a `POST` or a JSON API call for which a redirect to an
  HTML login page is useless and loses the request body. There's no
  `Accept`-header sniffing to choose `401` over `302` in this build.
- **SP metadata endpoint.** No schema field for its path; most real
  deployments exchange SP metadata with the IdP out-of-band anyway.

**Breaking change note**: `sp_base_url` is a required field with no
default. Any existing SAML source config predating this needs it added
— previously a SAML source only affected config validation, so this
couldn't have been silently relied upon before.

## Authorization (ACLs)

`acl` is a top-level list of rules, a sibling of `target` and `inbound`.
It decides which authenticated identities may use which methods and
paths.

```yaml
acl:
  - principals:
      - mode: basic
        username: ingest
    methods:
      - POST
    paths:
      - /api/v1/push
  - principals:
      - mode: jwt
        source: github
        claims:
          repository_owner: my-org
      - mode: saml
        claims:
          groups: admins
    methods:
      - GET
    paths:
      - /prometheus/*
```

- **No `acl` (or an empty one) allows everything** that passes
  authentication, exactly as if ACLs didn't exist.
- **With any rule, the default is deny.** A request is allowed if at
  least one rule matches it, and otherwise gets `403 forbidden`. A
  request that fails authentication still gets its usual `401` (or SAML
  redirect); ACLs only ever apply after authentication succeeds.
- **A rule matches** when its method, its path and at least one of its
  principals all match.
  - `methods`: any of the listed methods, case-insensitive. `*` matches
    every method. Omitted means every method.
  - `paths`: an exact path, or a prefix when it ends in `/*` (`/x/*`
    matches `/x/` and `/x/a/b`, not `/x` or `/xy`). Omitted means every
    path.
- **A principal matches** when its `mode` matches the auth mode that
  authenticated the request and every other field it sets matches:
  - `username`: the Basic username (`basic` only).
  - `source`: the `name` of the JWT source that verified the token
    (`jwt` only).
  - `claims`: JWT claims or SAML attributes (not available for
    `basic`). The JWT `sub` claim and the SAML NameID are both exposed
    as a `sub` claim, so match either with `claims: {sub: ...}` -
    there's no separate subject field for `jwt`/`saml`. A value matches
    a claim equal to it, or an array claim containing it. Numbers and
    booleans compare by their written form (`"42"`, `"true"`). Only
    top-level claims are matched.
- **Paths must be clean.** While any rule exists, a request path
  containing `..`, `.` or `//` segments, or an encoded slash (`%2F`),
  gets a `403`, since the backend might resolve it differently from the
  path the rules were matched against.
- **Mistakes fail the load, not the request.** An unknown `mode`, a
  `source` that isn't a configured JWT source, a Basic `username` that
  isn't a configured user, a principal with only `mode`, or a malformed
  method or path is a config error, and on hot-reload the previous
  config stays live.
- The SAML ACS path is never subject to ACLs, so login keeps working.
- With no auth mode enabled at all, a non-empty `acl` denies every
  request.
- Denials log `reason=acl_denied` with the mode, source, subject,
  method and path, and count toward
  `authn_rejections_total{reason="acl_denied"}`. The subject is never a
  metric label.

## Observability

- **`GET /metrics`** is always mounted, unauthenticated, in Prometheus
  exposition format — point a Prometheus scrape config at it directly.
  No flag/env var turns this off; it costs nothing extra to leave on.
- **Traces and logs**, and *additionally* pushing metrics via OTLP, are
  off until you configure them — no YAML/`TAP_` fields for this, only
  the [standard OpenTelemetry environment
  variables](https://opentelemetry.io/docs/specs/otel/protocol/exporter/)
  every OTel-instrumented service already reads, e.g.
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`,
  `OTEL_RESOURCE_ATTRIBUTES`, and the per-signal
  `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT` overrides. Setting
  the general endpoint (or a signal-specific one) turns that signal on;
  leaving all of them unset keeps the proxy fully inert on that front —
  no connection attempts, no export-failure log noise.
- Server-side spans (`otelhttp`) cover the proxied route only — not
  `/healthz` or `/metrics`, so probe/scrape traffic doesn't spam traces
  or double-count in its own metrics. Client-side spans cover every
  outbound call to the backend, and trace context propagates to it
  automatically.
- One custom metric: `authn_rejections_total{reason="..."}` — a
  Prometheus counter (regardless of OTLP config, since `/metrics` is
  always live) attributed by the same rejection reason already used in
  structured logs (`no_credential`, `bad_signature`, `expired`,
  `keys_unavailable`, `bad_credential`, `saml_metadata_unavailable`,
  `acl_denied`, ...). Generic HTTP metrics can't tell you *why* a request got a
  401/403/503; this can.
- Logs stay the same stdout JSON either way (`slog`); when trace export
  is configured, request-scoped log lines additionally carry
  `trace_id`/`span_id` and get forwarded to the OTel Logs SDK.
- This is a meaningfully larger dependency footprint than the rest of
  this project (the OTel SDK, its OTLP exporters, and
  `prometheus/client_golang`) — the accepted cost of speaking the real
  OTLP wire protocol rather than a lighter, non-standard alternative.

## Running locally

```sh
make run   # builds and runs against config.example.yaml
```

Or directly:

```sh
go build -o bin/token-auth-proxy ./cmd/token-auth-proxy
./bin/token-auth-proxy --config config.example.yaml
```

## Docker

```sh
docker build -t token-auth-proxy .
docker run -p 8080:8080 \
  -v $(pwd)/config.example.yaml:/etc/token-auth-proxy/config.yaml:ro \
  token-auth-proxy
```

Multi-arch (`linux/amd64` + `linux/arm64`) builds are validated in CI on
every push/PR and published to
[`ghcr.io/thisisqasim/token-auth-proxy`](https://github.com/ThisIsQasim/token-auth-proxy/pkgs/container/token-auth-proxy)
on merges to `main` (tagged by commit SHA).

## Testing

```sh
make test              # unit tests, race detector
make test-integration  # exec's the real binary; proves hot-reload end-to-end
make test-load         # soak test: config keeps flipping under concurrent traffic
make test-all          # all three
make bench             # throughput/allocation benchmark (not gated in CI)
```

`test-integration` and `test-load` build and run the real binary as a
subprocess rather than mocking anything — they need Go installed but
nothing else.

## Releases

Pushing a `vX.Y.Z` tag triggers [GoReleaser](https://goreleaser.com/) to:

- cross-compile binaries for linux/darwin/windows × amd64/arm64,
- publish a GitHub Release with archives, `checksums.txt`, and a
  changelog,
- build and push a multi-arch (`linux/amd64` + `linux/arm64`) Docker
  image to `ghcr.io/thisisqasim/token-auth-proxy:X.Y.Z` (note: no `v`
  prefix on the image tag — GoReleaser's `{{ .Version }}` strips it, even
  though the git tag itself is `vX.Y.Z`) and `:latest`.

Validate release config changes locally without publishing anything:

```sh
make release-dry-run
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md), particularly the one-time
`pre-commit install` step — commits are expected to pass `gofmt`,
`goimports`, `go vet`, and `golangci-lint` before they land.
