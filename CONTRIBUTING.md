# Contributing

## Setup

- Go 1.26.5 or newer (the toolchain will auto-download it if you have an
  older one and `GOTOOLCHAIN=auto`, the default).
- Install [pre-commit](https://pre-commit.com/) once per machine:
  ```sh
  pip install pre-commit   # or: brew install pre-commit / uvx pre-commit
  pre-commit install
  ```
  This wires up `gofmt`, `goimports`, `go vet`, `golangci-lint`, and
  `go mod tidy` to run on every commit. Install `golangci-lint` and
  `goimports` locally so the hooks have something to invoke:
  ```sh
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
  go install golang.org/x/tools/cmd/goimports@latest
  ```

## Before pushing

```sh
make fmt
make lint
make test-all   # unit + integration + load tests
```

CI runs the same checks (`lint`, `test`, `test-integration`, `load-test`,
`docker`) on every push and pull request against `main`.

## Pull requests

- Keep changes scoped — one logical change per PR.
- Add or update tests for any behavior change; this repo has unit,
  integration, and load test suites for a reason (see the [README](./README.md#testing)).
- Commit messages: short, imperative summary line (`Fix debounce timer
  leak`, not `Fixed` or `Fixes`). No enforced format beyond that.

## Cutting a release

Maintainers only: push a `vX.Y.Z` tag to `main`. See the
[README](./README.md#releases) for what that triggers.
