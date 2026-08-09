# token-auth-proxy

A minimal HTTP reverse proxy built on Go's standard library (`net/http` /
`net/http/httputil`). It forwards every request to a single backend
target defined in a YAML config file, and hot-reloads that target from
disk without a process restart — no auth or routing logic yet, this is
the foundation those get built on.

## How it works

- The proxy watches its config file's parent directory for changes
  (covers plain in-place writes, atomic rename-based saves, and
  Kubernetes ConfigMap volume symlink-swaps alike) and debounces bursts
  of filesystem events into a single reload.
- Only `target` is hot-reloaded. `listen_addr` and `timeouts` are read
  once at startup; changing them requires a restart.
- A malformed or invalid config write is logged and discarded — the
  previously loaded config stays live, so a transient bad write never
  takes the proxy down.
- The backend target swaps atomically: a request already in flight when
  the target changes always completes against the backend it started
  with.

## Configuration

See [`config.example.yaml`](./config.example.yaml):

```yaml
listen_addr: ":8080"
target: "http://localhost:9000"
timeouts:
  read_header: 5s
  read: 30s
  write: 30s
  idle: 120s
  dial: 5s
  response_header: 15s
```

`GET /healthz` always returns `200 OK` without touching the backend —
mount it as a Kubernetes liveness/readiness probe.

## Running locally

```sh
make run   # builds and runs against config.example.yaml
```

Or directly:

```sh
go build -o bin/token-auth-proxy ./cmd/token-auth-proxy
./bin/token-auth-proxy -config config.example.yaml
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
