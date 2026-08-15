# Guide: JWT authentication

This guide walks through configuring JWT bearer verification end to
end, using a real local Keycloak instance and a real signed token —
copy, paste, run. For the exhaustive rule-by-rule reference (exact
verification order, every field), see the [main README's JWT
section](../../README.md#jwt-enforced).

## How it works, briefly

A request matching a configured, non-disabled JWT source's `issuer`
must carry a valid token or the proxy responds `401` before the request
reaches the backend. The token's own (unverified) `iss` claim picks
*which* configured source verifies it; everything after that — key
lookup, signature, `exp`/`nbf`, `aud`, `iss` — is enforced against that
source's configuration, never against anything the token claims about
itself. With zero JWT sources configured (and no SAML source enabled
either), nothing is enforced and every request passes through.

## Try it locally

You'll need an issuer to trust and a token signed by it.
[Keycloak](https://www.keycloak.org/) has an official Docker image and
works for this.

```sh
docker run -d --name keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Give it a few seconds to start, then create a realm and a client
(`kcadm.sh`, Keycloak's admin CLI, ships inside the image — this is
scriptable, no admin console clicking required):

```sh
docker exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin

docker exec keycloak /opt/keycloak/bin/kcadm.sh create realms -s realm=demo -s enabled=true

docker exec keycloak /opt/keycloak/bin/kcadm.sh create clients -r demo \
  -s clientId=my-app -s enabled=true -s publicClient=false \
  -s serviceAccountsEnabled=true -s 'redirectUris=["*"]' -i
# prints the new client's UUID, e.g. 34c6f72f-a12b-4868-90f1-9164811ff015

docker exec keycloak /opt/keycloak/bin/kcadm.sh get clients/<uuid>/client-secret -r demo
# {"type":"secret","value":"<client secret>"}
```

`serviceAccountsEnabled=true` is what turns on the `client_credentials`
grant below — this is a machine-to-machine client, not a user login.
Keycloak's discovery document and JWKS are now live for that realm:

```sh
curl http://localhost:8080/realms/demo/.well-known/openid-configuration
# {"issuer":"http://localhost:8080/realms/demo","jwks_uri":"http://localhost:8080/realms/demo/protocol/openid-connect/certs",...}
```

Configure the proxy to trust it:

```yaml
# config.yaml
listen_addr: ":8080"
target: "http://127.0.0.1:19091"   # your backend
inbound:
  auth:
    jwt:
      - name: my-issuer
        issuer: "http://localhost:8080/realms/demo"
        jwks_url: "http://localhost:8080/realms/demo/protocol/openid-connect/certs"
```

```sh
token-auth-proxy --config config.yaml --listen-addr 127.0.0.1:18092
```

Without a token, you get rejected. Get a real one from Keycloak's token
endpoint using the client ID/secret from above:

```sh
curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=my-app -d client_secret=<client secret> \
  | jq -r .access_token
```

(No `jq`? The response is `{"access_token":"...","expires_in":60,...}` —
copy the `access_token` value by hand.)

```sh
curl -i http://127.0.0.1:18092/
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: Bearer

curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." http://127.0.0.1:18092/
# (your backend's response)
```

The proxy's logs show exactly what happened:

```json
{"level":"INFO","msg":"jwt verification enabled","jwt_sources":1}
{"level":"INFO","msg":"rejected request","reason":"no_credential","path":"/"}
{"level":"INFO","msg":"built jwks resolver","source":"my-issuer","jwks_url":"http://localhost:8080/realms/demo/protocol/openid-connect/certs"}
```

Other OIDC providers (Okta, Auth0, Entra ID, Kubernetes' own API
server) use the same realm/client/token-endpoint shape, just different
URLs.

## Trusting multiple issuers

`inbound.auth.jwt` is a list — add as many sources as you need. A
request's own `iss` claim selects which source's keys/policy apply:

```yaml
inbound:
  auth:
    jwt:
      - name: internal-k8s
        issuer: "https://kubernetes.default.svc"
        jwks_url: "https://kubernetes.default.svc/openid/v1/jwks"
        audiences: ["token-auth-proxy"]

      - name: partner-oidc
        issuer: "https://partner.example.com"
        oidc_discovery_url: "https://partner.example.com/.well-known/openid-configuration"
        algorithms: ["RS256", "ES256"]
```

Pull one source out of rotation (or stage it before going live) with
`disabled: true` — no need to delete it, and it hot-reloads like
everything else here.

For two concrete, worked examples of this — trusting several
Kubernetes clusters at once, and trusting GitHub Actions' own OIDC
issuer — see the [Kubernetes guide](kubernetes-tokens.md) and the
[GitHub Actions guide](github-actions.md).

## OIDC discovery instead of a static JWKS URL

Set `oidc_discovery_url` instead of `jwks_url` and the proxy resolves
`jwks_uri` from the discovery document once, then treats it exactly
like a directly configured `jwks_url`. The discovery document's own
`issuer` must match your configured `issuer` — its advertised signing
algorithms are never consulted, only your own `algorithms` list is.

## Where the token comes from

By default the proxy looks for `Authorization: Bearer <token>`. Override
`credentials` per source to check other locations, tried in order,
first successful extraction wins:

```yaml
inbound:
  auth:
    jwt:
      - name: my-issuer
        issuer: "http://localhost:8080/realms/demo"
        jwks_url: "http://localhost:8080/realms/demo/protocol/openid-connect/certs"
        credentials:
          - location: header
            name: Authorization
            prefix: "Bearer "
          - location: cookie
            name: session
```

Avoid `location: query` where you can — a token in the URL ends up in
access logs and `Referer` headers.

## Overriding without touching the config file

`inbound.auth.jwt` can also be set (or replaced entirely) via an env
var, useful for injecting a source in CI or a container without editing
a mounted file:

```sh
export TAP_INBOUND_AUTH_JWT_JSON='[{"name":"internal-k8s","issuer":"https://kubernetes.default.svc","jwks_url":"https://kubernetes.default.svc/openid/v1/jwks"}]'
```

This is a full JSON array replacing the whole list, not merged with the
file's — see the [hot-reload guide](hot-reload.md) for how this
interacts with a `--config` file's own value.

## Common pitfalls

- **`algorithms` defaults to `["RS256"]` only.** If your IdP signs with
  `ES256` or another algorithm, list it explicitly — the token's own
  `alg` header is never trusted to pick the verification algorithm
  (this is deliberate: see [RFC 8725 §3.1](https://www.rfc-editor.org/rfc/rfc8725#section-3.1)
  on algorithm confusion attacks).
- **Tokens with no `exp` claim are always rejected.** There's no way to
  configure around this.
- **The rejection reason never reaches the client** — only a generic
  `401` and `WWW-Authenticate` header. Check the proxy's own logs (or
  `authn_rejections_total{reason="..."}` — see the
  [observability guide](observability.md)) to see *why* a request was
  rejected.
