# token-auth-proxy

A minimal HTTP reverse proxy built on Go's standard library (`net/http` /
`net/http/httputil`). It forwards every request to a single backend
target, configured via a YAML file (with hot-reload), CLI flags, and/or
environment variables. It can check inbound HTTP Basic credentials,
verify JWT bearer tokens, and/or enforce an interactive SAML SP login
before forwarding (see [Auth](#auth) below) — there's still no per-path
routing, every request goes to the same `target` regardless of which
auth mode (if any) it satisfied.

📖 **New here?** This README is the exhaustive technical reference. For
an introduction, example use cases, a getting-started walkthrough, and
task-oriented guides (Basic, JWT, SAML, hot-reload, observability), see
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
  restart, not silently ignored. Everything else — `target` and
  `inbound.auth` (the trusted Basic/JWT/SAML sources — see
  [Auth](#auth) below) — hot-reloads at runtime.
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
describe trusted credential sources. `outbound` is reserved for a later
pass (rewriting credentials on the backend leg, e.g. verifying an
inbound SAML assertion and minting an outbound OIDC-style JWT). See
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
  unverified field.
- **Key material**: a `jwks_url` or `oidc_discovery_url` (exactly one).
  An OIDC discovery document's `jwks_uri` is resolved once and then
  treated exactly like a directly configured `jwks_url`; the
  document's `issuer` must match the source's configured `issuer`, and
  its advertised signing algorithms are never consulted.
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
- **ACS callback** (`acs_path`): the IdP's `POST`ed assertion is
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
  `idp_metadata_cache_ttl` (default 1h); a refresh failure keeps serving
  the last-known-good metadata rather than logging every active session
  out, but the *first* fetch (nothing cached yet) fails closed — there's
  no sensible degraded behavior without at least one working fetch.
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
4. Otherwise, if **SAML** is enabled, it makes the redirect-or-forward
   decision. Note this comes *before* step 5, so with SAML enabled a
   credential-less request is redirected to the IdP and never sees a
   Basic challenge — basic auth then only serves clients that send the
   header proactively, with no browser password prompt.
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
  ...). Generic HTTP metrics can't tell you *why* a request got a
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
