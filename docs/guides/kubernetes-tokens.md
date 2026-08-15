# Guide: Kubernetes service account tokens

Every pod already gets a signed JWT via its service account — no need
to mint and distribute a separate API key for one workload to call
another through this proxy. This guide covers trusting tokens from the
cluster the proxy itself runs in, and from multiple clusters at once.

## How it works, briefly

Kubernetes signs a JWT for every pod's service account: the default
token mounted at
`/var/run/secrets/kubernetes.io/serviceaccount/token`, or a shorter-lived,
audience-bound one requested via a projected volume or the
`TokenRequest` API. Either way it carries the same shape — `iss`, `aud`,
`exp`/`nbf`/`iat`, and `sub` in the form
`system:serviceaccount:<namespace>:<name>` — signed by the cluster's own
key. Point this proxy's `issuer`/`jwks_url` at that cluster and it
verifies the signature the same way it verifies any other JWT.

## Single cluster, proxy running inside it

If the proxy runs as a pod in the same cluster whose service accounts
you're trusting, the cluster's own API server is the issuer:

```yaml
inbound:
  auth:
    jwt:
      - name: in-cluster
        issuer: "https://kubernetes.default.svc"
        jwks_url: "https://kubernetes.default.svc/openid/v1/jwks"
        audiences: ["my-api"]
```

`https://kubernetes.default.svc` is the default issuer on most
clusters, but it can be overridden by the cluster's own
`--service-account-issuer` flag — check with whoever manages the
cluster if you're not sure. `/openid/v1/jwks` is served without
requiring API-server authentication (Kubernetes deliberately exempts
it, the same way `/healthz` is exempt, specifically so external
verifiers like this proxy don't need their own API-server credentials
just to fetch keys).

Get a real, audience-bound token to test with:

```sh
kubectl create token default --audience=my-api
```

(Requires the caller to have `create` permission on
`serviceaccounts/token` for that service account — most clusters allow
this by default for a service account acting on itself.)

```sh
curl -H "Authorization: Bearer $(kubectl create token default --audience=my-api)" \
  http://token-auth-proxy.default.svc/
```

A workload that isn't using `kubectl` gets the same kind of token via a
projected volume in its pod spec:

```yaml
volumes:
  - name: my-api-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: my-api
            expirationSeconds: 3600
```

The kubelet refreshes it automatically before it expires; read it from
`/var/run/secrets/tokens/my-api-token` inside the container.

## Multiple clusters

Managed Kubernetes (EKS, GKE, AKS) gives each cluster its own public,
per-cluster OIDC issuer — the same mechanism behind
IRSA/Workload-Identity-style federation, reused here directly with no
cloud SDK involved, just JWT verification. `inbound.auth.jwt` is
already a list, so trusting several clusters at once is just one
source per cluster:

```yaml
inbound:
  auth:
    jwt:
      - name: cluster-a
        issuer: "https://oidc.cluster-a.example.com"
        jwks_url: "https://oidc.cluster-a.example.com/openid/v1/jwks"
        audiences: ["my-api"]

      - name: cluster-b
        issuer: "https://oidc.cluster-b.example.com"
        jwks_url: "https://oidc.cluster-b.example.com/openid/v1/jwks"
        audiences: ["my-api"]
```

A request's own `iss` claim picks which cluster's keys verify it —
nothing else to configure for routing between them. Check your cloud
provider's docs for the exact issuer URL: EKS clusters expose theirs
under `oidc.eks.<region>.amazonaws.com/id/<cluster-id>`; GKE and AKS
have their own equivalents.

## What this doesn't check

This proxy verifies `iss`/`aud`/`exp`/`nbf`/signature — it doesn't look
at `sub`, so it can't tell "service account `payments` in namespace
`billing`" apart from any other service account in the same cluster
that can obtain a token with the same audience. It also doesn't forward
the token or its claims to your backend, so the backend can't do that
filtering either. In practice this proxy currently authenticates "some
workload in a trusted cluster," not "specifically this one service
account." If your namespace/RBAC boundaries already scope who can
request a token for a given audience, that may be enough; if you need
tighter, per-service-account restriction, this proxy's current feature
set can't express that yet.

See the [JWT authentication guide](jwt-authentication.md) for the
general verification rules, and the [main README](../../README.md#jwt-enforced)
for the exhaustive field reference.
