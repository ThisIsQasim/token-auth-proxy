# token-auth-proxy documentation

This is the narrative half of the docs — an overview, a getting-started
walkthrough, and a few task-specific guides. For the field-by-field
reference (every flag, every config field, every behavior edge case)
see the [main README](../README.md); this section links out to it
rather than repeating it.

## What is token-auth-proxy?

token-auth-proxy sits in front of a single backend and checks that a
request is authenticated before forwarding it. It forwards everything
it lets through unchanged to one configured `target` — no path-based
routing, no request rewriting, no load balancing.

It supports two ways of authenticating a request:

- **JWT bearer verification** — one or more trusted issuers, keys
  fetched from a JWKS URL or resolved via OIDC discovery, signature/
  expiry/audience checking. See the
  [JWT guide](guides/jwt-authentication.md).
- **SAML SP login** — an interactive Service Provider flow: redirect to
  the IdP, ACS callback, session cookie. See the
  [SAML guide](guides/saml-sso.md).

Neither one stores a credential in the proxy's own config: JWT
verification checks a signature against the issuer's keys, and SAML's
login flow means the password only ever goes to the IdP.

It also has:

- OpenTelemetry traces, metrics, and structured logs, plus an
  always-on `/metrics` endpoint. See the
  [observability guide](guides/observability.md).
- Config hot-reload with no restart. See the
  [hot-reload guide](guides/hot-reload.md).

It does one backend, one auth decision — no per-path routing, no
request/response transformation, no multiple backends. If you need
that, this isn't the tool for it.

## Where to go next

- **New here?** Start with [Getting Started](getting-started.md) —
  install the binary and configure JWT verification.
- **Setting up JWT verification?** → [JWT authentication guide](guides/jwt-authentication.md)
- **Trusting Kubernetes service account tokens (single- or multi-cluster)?** → [Kubernetes guide](guides/kubernetes-tokens.md)
- **Authenticating a GitHub Actions workflow?** → [GitHub Actions guide](guides/github-actions.md)
- **Setting up SAML SSO?** → [SAML SSO guide](guides/saml-sso.md)
- **Wiring up metrics/traces/logs?** → [Observability guide](guides/observability.md)
- **Deploying with live config changes (e.g. in Kubernetes)?** → [Hot-reload & configuration guide](guides/hot-reload.md)
- **Need the exact flag/env var/YAML field for something?** → the [main README](../README.md)'s Configuration, Auth, and Observability sections are the authoritative reference.
