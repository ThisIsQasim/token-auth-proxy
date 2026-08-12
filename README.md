# token-auth-proxy

A minimal HTTP reverse proxy built on Go's standard library (`net/http` /
`net/http/httputil`). It forwards every request to a single backend
target, configured via a YAML file (with hot-reload), CLI flags, and/or
environment variables — no auth or routing logic yet, this is the
foundation those get built on.

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
  `inbound.auth` (the trusted JWT/SAML sources — see
  [Auth](#auth-schema-only-not-yet-enforced) below) — hot-reloads at
  runtime.
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

A no-file, flags-only run, for example:

```sh
token-auth-proxy --target http://localhost:9000 --listen-addr :8080
```

`GET /healthz` always returns `200 OK` without touching the backend —
mount it as a Kubernetes liveness/readiness probe.

## Auth (schema only, not yet enforced)

The config supports describing trusted token sources so the proxy can
eventually verify incoming credentials — **this is schema only right
now**: nothing here is authenticated or rejected regardless of what's
configured. See [`config.example.yaml`](./config.example.yaml) for a
full commented-out YAML example.

- `inbound`/`outbound` are top-level config sections, siblings of
  `target`/`listen_addr`/`timeouts`. `inbound.auth` is designed;
  `outbound` is reserved for a later pass (rewriting credentials on the
  backend leg, e.g. verifying an inbound SAML assertion and minting an
  outbound OIDC-style JWT).
- `inbound.auth.jwt` is a **list** of trusted JWT issuers;
  `inbound.auth.saml` is **at most one** SAML source, not a list (no
  per-path routing exists to pick among multiple IdPs by). **There is no
  separate `enabled` switch** — a source counts as active unless it's
  `disabled: true`; the same field also lets you pull one JWT source out
  of rotation, or stage a source without going live, without touching
  the rest.
- A JWT source's `credentials` is a list of places to look for the
  token (header/cookie/query, each with an optional prefix like
  `"Bearer "`), tried in order — it defaults to the `Authorization`
  header if omitted. Key material comes from a `jwks_url` or
  `oidc_discovery_url` (exactly one); `algorithms` defaults to
  `["RS256"]`.
- The SAML source describes a full interactive SP integration (IdP
  redirect, ACS callback, session cookie) — those routes/redirects/
  sessions don't exist yet; only the config shape does.
- Both `target` and `inbound.auth` hot-reload together when
  `--config`/`TAP_CONFIG` is set.
- `inbound.auth.jwt`/`inbound.auth.saml` are also settable via
  `--inbound-auth-jwt-json`/`TAP_INBOUND_AUTH_JWT_JSON` (a **JSON array**,
  fully replacing the list) and `--inbound-auth-saml-json`/
  `TAP_INBOUND_AUTH_SAML_JSON` (a **JSON object**, fully replacing the
  source) — not merged with the file's value, using the same snake_case
  field names as the YAML form:
  ```sh
  TAP_INBOUND_AUTH_JWT_JSON='[{"name":"internal-k8s","issuer":"https://kubernetes.default.svc","jwks_url":"https://kubernetes.default.svc/openid/v1/jwks"}]'
  ```
  The value is always inline JSON, never a file path — for a larger or
  more complex source list, use `--config`/`TAP_CONFIG` instead. Like
  every other override, a flag wins over its env var, and (when
  `--config` is also set) it's re-applied on every hot-reload, so it
  keeps winning over whatever the file says for that field. Duration
  fields inside the JSON (`jwks_cache_ttl`, `session_duration`, ...)
  should be written as strings (`"10m"`), the same as in YAML.

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
