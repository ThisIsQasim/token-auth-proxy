# Getting started

This walks through installing token-auth-proxy and configuring JWT
verification.

## Install

Pick whichever fits your workflow:

**Go install** (requires Go 1.26+):

```sh
go install github.com/ThisIsQasim/token-auth-proxy/cmd/token-auth-proxy@latest
```

**Download a release binary** — prebuilt archives for
linux/darwin/windows × amd64/arm64 are attached to every
[GitHub release](https://github.com/ThisIsQasim/token-auth-proxy/releases).

**Docker**:

```sh
docker pull ghcr.io/thisisqasim/token-auth-proxy:latest
```

**From source**:

```sh
git clone https://github.com/ThisIsQasim/token-auth-proxy.git
cd token-auth-proxy
make build   # -> bin/token-auth-proxy
```

**As a Kubernetes sidecar**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  initContainers:
    - name: token-auth-proxy
      image: ghcr.io/thisisqasim/token-auth-proxy:latest
      restartPolicy: Always
      env:
        - name: TAP_LISTEN_ADDR
          value: ":8080"
        - name: TAP_TARGET
          value: "http://127.0.0.1:9000"
        - name: TAP_INBOUND_AUTH_JWT_JSON
          value: '[{"name":"my-issuer","issuer":"https://issuer.example.com","jwks_url":"https://issuer.example.com/.well-known/jwks.json"}]'
      ports:
        - containerPort: 8080
  containers:
    - name: app
      image: my-app:latest
      ports:
        - containerPort: 9000
```

## Configure JWT verification

```yaml
# config.yaml
listen_addr: ":8080"
target: "http://127.0.0.1:19091"   # your backend
inbound:
  auth:
    jwt:
      - name: my-issuer
        issuer: "https://issuer.example.com"
        jwks_url: "https://issuer.example.com/.well-known/jwks.json"
```

```sh
token-auth-proxy --config config.yaml
```

A request with no token, or an invalid one, gets `401` before it
reaches your backend:

```sh
curl -i http://127.0.0.1:8080/
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer
```

A request with a token signed by `my-issuer`'s keys, unexpired, passes
through unchanged. See the
[JWT authentication guide](guides/jwt-authentication.md) for a full
walkthrough against a real local identity provider (Keycloak),
including how to get a signed token to test with, multiple issuers,
and OIDC discovery.

## Next steps

Configure authentication sources:

- [Basic authentication guide](guides/basic-authentication.md) — a
  username and password, with no identity provider to set up.
- [JWT authentication guide](guides/jwt-authentication.md) — any
  JWT/OIDC issuer: multiple issuers, OIDC discovery, credential
  locations, common pitfalls.
- [Kubernetes guide](guides/kubernetes-tokens.md) — service account
  tokens, from one cluster or several.
- [GitHub Actions guide](guides/github-actions.md) — a CI workflow's
  own token, no stored repo secret.
- [SAML SSO guide](guides/saml-sso.md) — interactive browser-based
  login instead of a bearer token.

Everything else:

- [Observability guide](guides/observability.md) — the `/metrics`
  endpoint, OpenTelemetry traces/logs, the `authn_rejections_total`
  metric.
- [Hot-reload & configuration guide](guides/hot-reload.md) — config
  precedence, Kubernetes ConfigMap patterns, staging changes safely.
- The [main README](../README.md) for the complete flag/env
  var/config-field reference.
