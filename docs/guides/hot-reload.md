# Guide: Hot-reload & configuration

token-auth-proxy is built around the idea that auth policy and backend
target are things you'll change more often than you want to restart a
process for — a rotated JWKS endpoint, a new trusted issuer, a backend
migration. This guide covers how config layering and live reload
actually behave, and how to use them safely, including in Kubernetes.
For the field-by-field reference, see the [main README's Configuration
section](../../README.md#configuration).

## The three layers, and their precedence

Every setting can come from a flag, an environment variable
(`TAP_`-prefixed), or a YAML file field — in that precedence order:
**flag > env > file > built-in default**. Concretely:

- `--config`/`TAP_CONFIG` points at a YAML file. When set, the proxy
  watches that file's parent directory and reloads on changes.
- Every other flag/env var is **re-applied on top of the file on every
  load, including every hot-reload** — so a `--target` flag keeps
  winning even if the file's `target` changes underneath it, while any
  field you *didn't* override keeps hot-reloading normally from the
  file.
- If `--config`/`TAP_CONFIG` isn't set at all, the proxy runs with a
  static configuration built entirely from flags/env — no file, no
  watch, no hot-reload, ever.

This means you can, for example, pin `--listen-addr` via a flag while
letting `target` and `inbound.auth` hot-reload freely from a mounted
file — the flag simply never loses to the file for that one field.

## What hot-reloads and what doesn't

`target` and `inbound.auth` (JWT sources, the SAML source, the Basic
source and its user list) hot-reload at runtime — add, remove, edit, or
(re-)enable a source and it takes effect on the next request.
`listen_addr` and `timeouts` are read once at startup; a later file
change to those is logged as requiring a restart, not silently ignored
or silently applied.

Removing a basic-auth user is immediate: the proxy caches verified
credentials for a few minutes to avoid paying bcrypt's cost per
request, but any change to the basic source throws that cache away.

The backend target swap is atomic: a request already in flight when the
target changes always completes against the backend it started with —
there's no window where an in-progress request gets a half-old,
half-new view of config.

## Safety behavior

A malformed or invalid config write is logged and discarded — the
previously loaded config stays live. This matters in practice because
file writes aren't always atomic from the proxy's point of view (an
editor, or a deploy tool, can leave a file briefly truncated or
half-written mid-save); a transient bad read never takes the proxy
down, it just skips that reload and keeps serving the last good config.

Bursts of filesystem events (an editor writing a file in several small
operations, for instance) are debounced into a single reload rather
than reloading once per individual write.

## Staging a change before it goes live

There's no separate `enabled` switch for a JWT or SAML source — a
source is active unless it's `disabled: true`. Use that to stage a
fully-written source (new issuer, new SAML IdP) in the file ahead of
time without it taking effect, then flip `disabled` off when you're
ready — one small, reviewable diff instead of writing the whole source
in one go.

```yaml
inbound:
  auth:
    jwt:
      - name: new-partner-oidc
        issuer: "https://partner.example.com"
        oidc_discovery_url: "https://partner.example.com/.well-known/openid-configuration"
        disabled: true   # staged, not live yet
```

## Kubernetes: mounting config from a ConfigMap

The file watcher is specifically designed to handle how Kubernetes
updates a mounted ConfigMap: it's not an in-place edit, it's an atomic
symlink swap of the whole directory (`..data` pointing at a new
timestamped directory). Point `--config`/`TAP_CONFIG` at the mounted
path and a `kubectl apply`/`kustomize`/GitOps update to the ConfigMap
propagates the same way an in-place file edit would locally — no pod
restart, no rollout.

```yaml
volumeMounts:
  - name: proxy-config
    mountPath: /etc/token-auth-proxy
volumes:
  - name: proxy-config
    configMap:
      name: token-auth-proxy-config
```

```sh
token-auth-proxy --config /etc/token-auth-proxy/config.yaml
```

Two things worth knowing before relying on this:

- ConfigMap updates aren't instant — kubelet's own sync interval (up to
  a minute or so, depending on cluster settings) applies *before* the
  proxy's own debounce even sees the change.
- `listen_addr`/`timeouts` still won't hot-reload even from a
  ConfigMap — those changes need a rollout, same as anywhere else.

## Value references and reloads

Any string in the config *file* can come from elsewhere, and is
re-resolved on **every** reload:

```yaml
target: "${env:BACKEND_URL}"
password_hash: "${file:/run/secrets/alice.bcrypt}"
```

Full rules are in the [README](../../README.md#value-references-env--file);
what matters for reloading:

- **A referenced file isn't watched.** Only the config file's directory
  is. Rotating a mounted Secret won't trigger a reload on its own —
  touch the config file (or roll the pods) if you need it immediate.
- **A broken reference fails the reload, not just startup.** Unset the
  environment variable a file references and the next reload is
  rejected, keeping the previous config live — same as a malformed file.
- **Only the file layer is interpolated.** Flags, `TAP_` vars and the
  `TAP_*_JSON` blobs below are literal.

## Overriding a list/object field via env var

`inbound.auth.jwt`, `inbound.auth.saml` and `inbound.auth.basic` can
also be set via `TAP_INBOUND_AUTH_JWT_JSON` (a JSON array),
`TAP_INBOUND_AUTH_SAML_JSON` and `TAP_INBOUND_AUTH_BASIC_JSON` (JSON
objects) — inline JSON, never a file path, using the same snake_case
field names as YAML. Like any other env
var, this **fully replaces** the file's value for that field (not
merged) and is re-applied on every hot-reload, so it keeps winning over
whatever the file says. Useful for injecting a source from a secrets
manager or CI without templating the YAML file itself; for anything
longer than a source or two, prefer the file.

## Troubleshooting a reload that didn't take effect

1. Check the logs — every accepted reload logs `"config reloaded"` with
   the new `target`/`auth_enabled`/`jwt_sources`/`saml_configured`/
   `basic_configured` summary; a rejected one logs `"config reload failed, keeping
   previous config"` with the parse/validation error instead, and keeps
   the old config live.
2. Confirm you didn't change `listen_addr`/`timeouts` — those need a
   restart, and the proxy logs that explicitly rather than reloading
   them.
3. Confirm nothing is overriding the field via flag/env — those always
   win over the file, hot-reload or not.
