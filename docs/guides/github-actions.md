# Guide: Authenticating GitHub Actions workflows

Let a GitHub Actions workflow call a backend behind this proxy without
a stored repo secret or PAT. GitHub mints a short-lived, workflow-scoped
OIDC token for every job run — verify that instead of managing a
credential by hand.

## Enable it in your workflow

Requesting a token needs `id-token: write`, which is off by default:

```yaml
permissions:
  id-token: write
```

## Get a token inside the job

GitHub injects `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` into any step that has `id-token: write`
— use them to fetch a real token and call your proxy:

```yaml
- name: Call the backend
  run: |
    TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=my-api" | jq -r .value)
    curl -H "Authorization: Bearer $TOKEN" https://my-api.example.com/
```

`audience` is a string *you* choose when requesting the token — it has
to match what the proxy's `audiences` list expects, but it isn't a
GitHub-verified identifier of your repository (see the caveat below).

## Configure the proxy

```yaml
inbound:
  auth:
    jwt:
      - name: github-actions
        issuer: "https://token.actions.githubusercontent.com"
        oidc_discovery_url: "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
        audiences: ["my-api"]
```

Both URLs are real and public — `oidc_discovery_url`'s document points
at `https://token.actions.githubusercontent.com/.well-known/jwks` for
keys, and GitHub signs these tokens with RS256, matching the proxy's
default `algorithms`, so nothing else needs setting.

## This doesn't restrict by repository — read this before relying on it

`token.actions.githubusercontent.com` is the same issuer for *every*
repository on GitHub — yours, a stranger's, a bot's. The token's `sub`
claim (e.g. `repo:your-org/your-repo:ref:refs/heads/main`) is what
actually identifies which repo/branch/environment issued it, and it's
not forgeable — GitHub sets it from the real workflow context. But this
proxy only checks `iss`/`aud`/`exp`/`nbf`/signature; it never looks at
`sub` or any other claim, and it doesn't forward the token or its
claims to your backend either. Setting `audiences` doesn't close this
gap: the audience is a string the *workflow author* picks when
requesting the token, not something GitHub restricts per repository —
any workflow, in any repository, can request the same audience string
and get a token that passes this proxy's check.

**In practice**, trusting this issuer currently authenticates "some
GitHub Actions workflow requested a token for this audience" — not
"my repository's workflow, specifically." If you need to restrict to
one repository or organization, which most real deployments should,
this proxy's current feature set can't express that on its own; don't
put anything behind GitHub Actions verification alone that you
wouldn't be comfortable exposing to any GitHub Actions run on the
internet with the right audience string.

One partial, practical mitigation if your repository is **private**:
pick an unpublished, hard-to-guess `audience` value and don't put it
anywhere a stranger could read it. Since the string only exists in your
own workflow file, this functions as a shared secret of sorts — weaker
than real per-repo verification, but better than a guessable one like
`"my-api"`. It offers nothing for a **public** repository, since anyone
can just read the audience value out of your workflow file.

See the [JWT authentication guide](jwt-authentication.md) for the
general verification rules, and the [main README](../../README.md#jwt-enforced)
for the exhaustive field reference.
