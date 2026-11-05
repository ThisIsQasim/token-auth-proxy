# Guide: Prom label proxy

Give several tenants one Prometheus and let each see only its own series, with the tenant
taken from the caller's token. The proxy adds a label matcher to everything a caller
reads, so nobody has to run a separate label-enforcing proxy or trust a header. For the
field-by-field reference see the [main README's section](../../README.md#prometheus-label-enforcement).

The backend can be anything serving the Prometheus HTTP API, optionally with the
Alertmanager v2 API under the same proxy.

## How it works

Label enforcement runs after authentication and the [ACL](acls.md). Every request then ends
in one of three ways:

- **Exempt:** the caller is listed under `exempt`, and the request is forwarded unchanged.
- **Enforced:** a rule matches the caller, each of its labels gets a value from their
  claims, and the path is one the proxy knows how to enforce.
- **Refused:** anything else gets a `403` without touching the backend.

## Map a claim to a label

Suppose your identity provider puts tenants in a `groups` claim, next to groups that have
nothing to do with tenancy:

```json
{
  "sub": "alice",
  "groups": ["tenant-acme", "staff"]
}
```

Your series carry a `namespace` label. This takes the part after `tenant-`, and drops
`staff` because it does not match:

```yaml
target: http://prometheus:9090
inbound:
  auth:
    jwt:
      - name: idp
        issuer: https://idp.example.com
        jwks_url: https://idp.example.com/jwks
outbound:
  prom_label_proxy:
    rules:
      - principals:
          - mode: jwt
            source: idp
        labels:
          - name: namespace
            claim: groups
            pattern: "tenant-(.+)"
```

What the backend receives for Alice, whose token gives one value:

| Caller sends | Backend receives |
|---|---|
| `up` | `up{namespace="acme"}` |
| `sum(rate(http_requests_total[5m]))` | `sum(rate(http_requests_total{namespace="acme"}[5m]))` |
| `up{namespace="acme"}` | `up{namespace="acme"}` |
| `up{namespace="globex"}` | Nothing: the caller gets a `400` |

A token with both `tenant-acme` and `tenant-globex` gives `up{namespace=~"acme|globex"}`, and
that caller can narrow it with a matcher of their own. A token with no matching group gets a
`403`.

`pattern` has to match a whole value. Without a capture group the whole value is the label
value, and without a `pattern` every value of the claim is used.

## Different sources, different claims

Rules are tried in order and the first whose `principals` match applies. Give each source
its own rule when they carry identity differently. Kubernetes service account tokens have
the namespace inside `sub`:

```yaml
rules:
  - principals:
      - mode: jwt
        source: idp
    labels:
      - name: namespace
        claim: groups
        pattern: "tenant-(.+)"
  - principals:
      - mode: jwt
        source: k8s
    labels:
      - name: namespace
        claim: sub
        pattern: "system:serviceaccount:([^:]+):.+"
```

A rule with several labels enforces all of them together. `mode: jwt` or `mode: saml` with
nothing else matches every such caller. SAML attributes work the same way as claims.

## Let some callers through

Basic users have no claims, and writers and admins should not be limited to a label. List
them under `exempt`, which forwards them unchanged on any path:

```yaml
outbound:
  prom_label_proxy:
    exempt:
      - mode: basic
        username: writer
    rules:
      # ...
```

Use the [ACL](acls.md) to limit what an exempt caller can reach. An ACL that lets `writer`
`POST` to the push path keeps it away from your query API.

## Paths

Rule-matched callers can only reach the endpoints the proxy enforces, which the
[reference](../../README.md#prometheus-label-enforcement) lists. Everything else is a `403`,
including `/api/v1/read`, since there is nothing to add a matcher to.

If the API sits under a base path on the target, name it. Alertmanager behind the same target
is usually one too:

```yaml
outbound:
  prom_label_proxy:
    path_prefixes:
      - /prometheus
      - /alertmanager
```

`passthrough_paths` opens other paths to rule-matched callers, unchanged:

```yaml
outbound:
  prom_label_proxy:
    passthrough_paths:
      - /api/v1/status/buildinfo
```

Nothing is enforced on these paths, so only list ones that carry no tenant data. Grafana asks
for `/api/v1/status/buildinfo` and `/api/v1/metadata`, but the second lists metric names
across every tenant, so leave it out unless that is fine with you.

## Rules, alerts and silences

`/api/v1/rules` and `/api/v1/alerts` are filtered in the response: a caller sees only entries
that carry every enforced label with a value they hold. A rule with no such label is hidden
from everyone but exempt callers, so give tenant rules the label.

A silence belongs to a caller when it has an equality matcher on each enforced label, with a
value they hold. They list only their own, and can only update or delete their own.

To create one, a caller with a single value needs nothing extra: the proxy sets the matcher.
A caller with several values names one, or gets a `400`:

```json
{
  "matchers": [
    {"name": "namespace", "value": "acme", "isRegex": false},
    {"name": "alertname", "value": "HighLatency", "isRegex": false}
  ],
  "startsAt": "2026-11-05T10:00:00Z",
  "endsAt": "2026-11-05T12:00:00Z",
  "createdBy": "alice",
  "comment": "Deploying"
}
```

At least one matcher besides the enforced labels is required, so a tenant cannot silence all
of its alerts at once by accident. A regex or a negative matcher on an enforced label is
a `403`.

## Troubleshooting

A refusal by this feature counts under the `prom_label_denied` reason of `authn.rejections`.
The log line gives the cause in its `detail` field:

| `detail` | Meaning | Fix |
|---|---|---|
| `no_rule` | No rule matches the caller | Add a rule, or list them under `exempt` |
| `no_label_value` | The claim is missing, or no value matched `pattern` | Check the token's claims against `claim` and `pattern` |
| `unenforced_path` | The path is not an enforced endpoint | Check `path_prefixes`, or add it to `passthrough_paths` |
| `unclean_path` | The path has `..`, `//` or an encoded `/` | Fix the client |
| `no_identity` | No inbound auth method accepted the request | Check `inbound.auth` |

Other responses:

| Status | Meaning |
|---|---|
| `400` | A query that does not parse, more than one `query` parameter, or a matcher that excludes every value the caller holds |
| `413` | A request body over 10 MiB |
| `415` | A POST query that is not `application/x-www-form-urlencoded` |
| `502` | A rules, alerts or silences response that could not be filtered, including one over 64 MiB. It is never forwarded unfiltered |

A mistyped key under `outbound`, or at the top level, fails the load. On a reload, the
previous configuration keeps running.
