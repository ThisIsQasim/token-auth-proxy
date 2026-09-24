# Guide: ACLs

Restrict which authenticated identities may use which methods and paths
on the backend. For the field-by-field reference see the [main README's
ACL section](../../README.md#authorization-acls).

## How it works, briefly

Authentication runs first, exactly as without ACLs. Once a request is
authenticated, the proxy checks it against the top-level `acl` rules:

- No `acl` at all: every authenticated request is allowed.
- Any rules: a request is allowed only if some rule matches its
  identity, method and path. Otherwise the proxy answers `403` without
  touching the backend.

A rule with no `methods` matches every method, and one with no `paths`
matches every path.

## Splitting writes from reads

A metrics backend often needs one credential that may only push and
another that may only query. One proxy can enforce both:

```yaml
listen_addr: ":8080"
target: "http://cortex:9009"
inbound:
  auth:
    basic:
      users:
        - username: ingest
          password_hash: "$2y$12$..."
        - username: grafana
          password_hash: "$2y$12$..."
acl:
  - principals:
      - mode: basic
        subject: ingest
    methods:
      - POST
    paths:
      - /api/v1/push
  - principals:
      - mode: basic
        subject: grafana
    methods:
      - GET
      - POST
    paths:
      - /prometheus/*
```

```sh
curl -u ingest:... -X POST http://127.0.0.1:8080/api/v1/push      # allowed
curl -u ingest:... http://127.0.0.1:8080/prometheus/api/v1/query  # 403
curl -u grafana:... http://127.0.0.1:8080/prometheus/api/v1/query # allowed
```

## Matching on JWT claims

A principal can match the JWT source that verified the token, its `sub`,
and any top-level claims. Here any GitHub Actions workflow from `my-org`
may deploy, and a Kubernetes service account may read:

```yaml
acl:
  - principals:
      - mode: jwt
        source: github
        claims:
          repository_owner: my-org
          ref: refs/heads/main
    paths:
      - /deploy/*
  - principals:
      - mode: jwt
        source: cluster
        subject: system:serviceaccount:monitoring:prometheus
    methods:
      - GET
```

Every field a principal sets must match. A claim value matches a claim
equal to it, or an array claim that contains it, so `groups: admins`
matches a token carrying `"groups": ["staff", "admins"]`. SAML
principals work the same way, with `subject` as the NameID and `claims`
as the assertion's attributes.

## Overriding without touching the config file

```sh
token-auth-proxy --target http://cortex:9009 \
  --inbound-auth-basic-json '{"users":[{"username":"ingest","password_hash":"$2y$12$..."}]}' \
  --acl-json '[{"principals":[{"mode":"basic","subject":"ingest"}],"methods":["POST"],"paths":["/api/v1/push"]}]'
```

`--acl-json` (or `TAP_ACL_JSON`) fully replaces the file's `acl`.

## Common pitfalls

- **A typo fails the load.** A Basic `subject` that isn't a configured
  user, or a `source` that isn't a configured JWT source's `name`, is
  rejected at startup (or on reload, keeping the previous config live)
  rather than silently never matching.
- **`/x/*` doesn't cover `/x`.** Add `/x` as its own entry if the bare
  path should be allowed too.
- **Odd paths are refused.** While any rule exists, paths with `..`,
  `.`, `//` or an encoded slash get a `403`.
- **`401` still means authentication failed.** A `403` always means the
  identity was recognized but no rule allows the request.
