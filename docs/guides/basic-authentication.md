# Guide: Basic authentication

Put a username and password in front of a backend, with no identity
provider to set up. For the field-by-field reference see the [main
README's Basic section](../../README.md#basic-enforced).

Use this when the thing you're protecting has no users of its own: an
internal dashboard, a scrape endpoint, a staging environment. If you
already run an IdP, prefer [JWT](jwt-authentication.md) or
[SAML](saml-sso.md) — neither puts credential material in your config.

## How it works, briefly

A request must carry an `Authorization: Basic` credential matching a
configured user, or the proxy answers `401` with a `WWW-Authenticate:
Basic` challenge before the backend is touched. Browsers turn that
challenge into a login dialog; API clients send the header directly.

Passwords are stored only as bcrypt hashes. A plaintext password is
rejected at startup, naming the user — never silently accepted.

## Try it locally

Generate a hash with `htpasswd` (`apache2-utils` on Debian/Ubuntu,
`httpd-tools` on RHEL/Fedora):

```sh
htpasswd -bnBC 12 "" 'hunter2' | tr -d ':\n'
# $2y$12$QOOD13Yck.hsJKS7hrNR8uUtZn2ygUwHk.WmrC6r49jtPUgc7YX3W
```

`-B` selects bcrypt, `-C 12` sets the cost factor, and `tr` strips the
empty username's `:` and the trailing newline. Any bcrypt
implementation works if you don't have `htpasswd` handy.

```yaml
# config.yaml
listen_addr: ":8080"
target: "http://127.0.0.1:19091"   # your backend
inbound:
  auth:
    basic:
      realm: "internal tools"
      users:
        - username: alice
          password_hash: "$2y$12$QOOD13Yck.hsJKS7hrNR8uUtZn2ygUwHk.WmrC6r49jtPUgc7YX3W"
```

The hash goes in as-is — the `$` signs need no escaping.

```sh
token-auth-proxy --config config.yaml --listen-addr 127.0.0.1:18092

curl -i http://127.0.0.1:18092/
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: Basic realm="internal tools", charset="UTF-8"

curl -u alice:hunter2 http://127.0.0.1:18092/
# (your backend's response)
```

The logs say what happened:

```json
{"level":"INFO","msg":"basic auth enabled","realm":"internal tools","users":1}
{"level":"INFO","msg":"rejected request","reason":"no_credential","path":"/"}
{"level":"INFO","msg":"rejected request","reason":"bad_credential","path":"/","user":"alice"}
```

`bad_credential` covers both a wrong password and a username that
doesn't exist; nothing the client can observe distinguishes the two.

## Keeping hashes out of the config file

A bcrypt hash is a verifier, not a credential — it can't be replayed
against the proxy. Still, any string in the config file can come from
an environment variable or a file instead:

```yaml
users:
  - username: alice
    password_hash: "${file:/run/secrets/alice.bcrypt}"
  - username: ci
    password_hash: "${env:CI_USER_HASH}"
```

In Kubernetes that's an ordinary Secret mounted at `/run/secrets`. One
caveat: the proxy watches its *config file's* directory, so rotating
the Secret alone isn't noticed until the next config reload or a
restart — see the [hot-reload
guide](hot-reload.md#value-references-and-reloads).

## Adding and removing users

`users` is a plain list and hot-reloads like everything else — edit the
file or ConfigMap and the change applies on the next request. Removing
a user takes effect immediately, including for clients whose credential
was already verified. `disabled: true` turns the whole gate off without
deleting it.

## Overriding without touching the config file

```sh
export TAP_INBOUND_AUTH_BASIC_JSON='{"realm":"internal","users":[{"username":"alice","password_hash":"$2y$12$..."}]}'
```

Or `--inbound-auth-basic-json`, which wins over the env var. It fully
replaces the file's source rather than merging — see the [hot-reload
guide](hot-reload.md). The JSON is taken literally, so `${file:...}`
inside it is not resolved.

## Common pitfalls

- **`password_hash is not a bcrypt hash` at startup** means you pasted
  the password instead of its hash.
- **The cost factor is a latency decision.** Cost 12 is roughly a
  quarter-second of CPU per verification. Verified credentials are
  cached for a few minutes, so only a client's first request pays it.
- **With SAML also enabled**, a credential-less request is redirected
  to the IdP rather than challenged, so no browser prompt appears —
  basic auth then only serves clients that send the header themselves.
  See the [README's Auth section](../../README.md#auth).
- **The `Authorization` header reaches your backend** unchanged, like
  every other auth mode here.
