# MCP OAuth server

Let MCP clients such as Claude Code log in through the proxy and get a short-lived
token. Nobody is handed a long-lived secret, and with dynamic client registration a person
only needs the URL. The proxy enforces the token itself, so the backend needs no auth of its
own. One that has it can verify the same token and see who each request is for.

Any login the proxy can run in a browser works, and clients see no difference:

- SAML
- OIDC with a confidential client (client secret)
- OIDC with a public client (PKCE, no secret)
- Basic

The proxy keeps no state for this. Login requests, authorization codes and
refresh tokens are encrypted values that carry what they need, and the tokens
are JWTs verified with the proxy's public keys.

## How it works

1. A client calls the protected URL with no token. The proxy answers `401` with
   `WWW-Authenticate: Bearer resource_metadata="<sp_base_url>/_tap/oauth/protected-resource"`.
2. The client reads that document, finds the authorization server, registers itself if
   it has no client ID, and sends the browser to `/_tap/oauth/authorize` (authorization
   code with PKCE).
3. The proxy runs its normal login. When the person is identified it checks the
   [ACL](acls.md) and the denylist, then sends the browser back to the client with a code.
4. The client exchanges the code at `/_tap/oauth/token` for an access token and a
   refresh token, and calls the protected URL with `Authorization: Bearer ...`.
5. The proxy verifies the token like any other JWT, applies the ACL, and forwards
   the request with the token unchanged. A backend with its own auth can verify it too;
   one without ignores it.

## Configure the proxy

You need two keys. The signing key signs the tokens; the sealing key encrypts the
login state.

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.pem
openssl rand -base64 32 > seal.key
```

```yaml
target: http://backend:8080
inbound:
  auth:
    # Any login method: saml as here, an inbound.auth.jwt source with login, or basic.
    saml:
      # ...
  oauth_server:
    sp_base_url: https://mcp.example.com
    mcp_url: https://mcp.example.com/mcp
    sealing_keys:
      - ${file:/keys/seal.key}
    dynamic_registration:
      enabled: true
outbound:
  token:
    signing_keys:
      - kid: "2026-10"
        private_key: ${file:/keys/signing.pem}
acl:
  - principals:
      - mode: jwt
        source: tap-oauth
        claims:
          groups: mcp-users
    paths:
      - /mcp
```

`inbound.oauth_server` and `outbound.token` go together, and at least one way to log
in must be configured.

If the backend is an `https` URL whose certificate comes from a private CA, set
`target_ca_cert` to that CA bundle, for example `target_ca_cert: ${file:/etc/backend-ca/ca.crt}`.
It replaces the system roots for the backend connection, and the server name is still checked.

**`inbound.oauth_server`**

| Field | Default | Meaning |
|---|---|---|
| `sp_base_url` | required | The proxy's own origin as the browser sees it, with no path. The issuer is `<sp_base_url>/_tap/oauth` |
| `mcp_url` | required | The protected endpoint's public URL. Same origin as `sp_base_url`. Also the default token audience |
| `code_ttl` | `60s` | How long a login result and its authorization code are valid (5s to 5m) |
| `refresh_absolute_lifetime` | `24h` | How long after the login a refresh token can renew the session. Refreshing never extends it |
| `sealing_keys` | required | Base64 32-byte keys. The first seals; every key opens, which is how you rotate |
| `clients` | required unless `dynamic_registration` is on | Public clients (PKCE required, no secret). `redirect_uris` are exact `https` URLs, or `http` loopback URLs (`localhost`, `127.0.0.1`, `[::1]`) that match on any port |
| `dynamic_registration` | off | `enabled`, and `redirect_uris`: the `https` callbacks a client may register. Empty by default, which allows loopback only |
| `denylist.subjects` | none | Subjects (the token's `sub`, compared ignoring case, no surrounding whitespace) that are refused at login, at code exchange, at refresh and on every request |
| `disabled` | `false` | Takes the server out of rotation without deleting its configuration |

**`outbound.token`**

| Field | Default | Meaning |
|---|---|---|
| `signing_keys` | required | ES256 (P-256) private keys in PEM, each with a `kid`. The first signs; all are published and verify |
| `access_token_ttl` | `15m` | Access token lifetime (1m to 1h) |
| `audience` | `mcp_url` | The token's `aud`. The proxy checks it, and a backend that verifies tokens should too |
| `claims.subject`, `claims.email`, `claims.groups` | `sub`, `email`, `groups` | Which claim (JWT login) or attribute (SAML) of the person's login supplies each value. `sub` is the SAML NameID. Values are copied as they are |

The token carries `sub`, `email` (when the login has one) and `groups`. For a SAML
login whose roles arrive in an attribute called `Roles`, set `claims.groups: Roles`. A
Basic login uses the username as `sub` and has no email or groups.

## With SAML as the login

A request that is not a browser navigation (anything but a `GET` or `HEAD` that accepts
`text/html`) and has no SAML session gets the `401` with the `resource_metadata` challenge
rather than a redirect to the IdP, which is what an MCP client needs to find the login. A
valid SAML session cookie is accepted, and a browser is sent to the IdP.


## Control who gets a token

The ACL decides this twice. It is checked at login for the token the person would get
(as a `POST` to the `mcp_url` path), so someone who could never use it is refused then,
and again on every request the token makes. The rule in the configuration above shows the
shape: name the proxy's own tokens as `mode: jwt, source: tap-oauth`, and match the token's
claims. Leave out `claims` to let anyone who signs in through, and have the backend decide if it
can: with a backend that has no auth, that means anyone who signs in gets full access.

With no ACL rules, every authenticated person can reach every path. Keep the rule's
`paths` to the protected endpoint.

## The backend

**With no auth of its own**, there is nothing to configure. The proxy verifies every token and
applies the ACL, and the backend ignores the `Authorization` header it receives. Two things
follow:

- Make the backend reachable only through the proxy. Anything else that can reach it is
  unauthenticated.
- The ACL is the only access control, and the backend cannot tell people apart. Every tool
  call runs with whatever access the backend itself has.

**If it verifies JWTs**, it can trust the same token, which the proxy forwards unchanged.
Configure it to:

- Fetch the signing keys from `<sp_base_url>/_tap/oauth/jwks.json`, or discover them from
  `<sp_base_url>/_tap/oauth/.well-known/openid-configuration`. The backend must be able to
  reach that URL.
- Accept the issuer `<sp_base_url>/_tap/oauth` and the audience `outbound.token.audience`,
  which defaults to `mcp_url`.
- Take the user from `sub` and their groups from `groups`.

For a complete setup with a real backend, see the
[OpenSearch MCP with SAML example](opensearch-mcp-saml.md).

## Connect a client

Either let clients [register themselves](#let-clients-register-themselves), as the
configuration above does, or list each one in `clients` with the redirect URI it uses. A
client needs to support the OAuth authorization code flow with PKCE (S256), find the
authorization server from the `resource_metadata` in the `401`, and use a public client
ID. The proxy also serves the two documents at the well-known locations a client looks in when it does not follow
that hint: `/.well-known/oauth-protected-resource` (also with the MCP path appended) and,
for the issuer, `/.well-known/oauth-authorization-server/_tap/oauth` and
`/.well-known/openid-configuration/_tap/oauth`.

### Let clients register themselves

Dynamic client registration (RFC 7591) removes the client ID from the setup: the client
registers itself the first time and the person only enters the URL.

```yaml
inbound:
  oauth_server:
    dynamic_registration:
      enabled: true
      # The https callbacks a client may register, for hosted clients such as
      # claude.ai. Loopback http callbacks are always accepted and need no entry.
      redirect_uris:
        - https://claude.ai/api/mcp/auth_callback
```

`clients` becomes optional, and anything listed there keeps working. Registration needs no
credential and shows no consent screen, so the redirect URIs are the control: a client can
only register a callback on that list or on the machine's own loopback address, and a login
still needs the person to sign in. Registered clients hold nothing on the server, never
expire, and stop working as soon as their callback leaves the list or registration is turned
off. Replacing every sealing key revokes all of them.

### Claude Code

With dynamic registration on, add the server by its URL and log in:

```sh
claude mcp add --transport http my-server https://mcp.example.com/mcp
claude mcp login my-server
```

Without it, list the client. Claude Code redirects to `http://localhost:<port>/callback`,
and a loopback URI matches on any port:

```yaml
clients:
  - id: claude-code
    redirect_uris:
      - http://localhost/callback
```

Then add the server with the client ID, and log in:

```sh
claude mcp add-json my-server '{
  "type": "http",
  "url": "https://mcp.example.com/mcp",
  "oauth": {
    "clientId": "claude-code",
    "callbackPort": 8765
  }
}'
claude mcp login my-server
```

The URL must be the `mcp_url`. Claude Code finds the authorization server itself from the
`401`, so no metadata URL is needed. `/mcp` inside a session starts the same login. Over SSH
or in a container, `claude mcp login my-server --no-browser` prints the URL to open; after signing
in, paste the address the browser was sent to (`http://localhost:<port>/callback?code=...`)
back into the prompt. It needs a terminal.

Claude Code keeps the refresh token and renews the access token on its own; you sign in
again only after `refresh_absolute_lifetime`, or if you are removed with the denylist.

### claude.ai, Claude Desktop and Claude mobile

These apps share one connector and one callback URL, so one setup covers all of them. Add
the connector in **Customize > Connectors** (on a Team or Enterprise plan, an Owner adds it
in **Organization settings > Connectors**, and members then connect with their own account)
and enter the `mcp_url` as the server URL. The connector then shows up in the Claude mobile
apps for the same account, where you turn it on from the **+** menu of a chat.

With dynamic registration on and `https://claude.ai/api/mcp/auth_callback` in its
`redirect_uris`, leave the OAuth client setting on **Register automatically**.

Without it, list the client:

```yaml
clients:
  - id: claude-ai
    redirect_uris:
      - https://claude.ai/api/mcp/auth_callback
```

Under the OAuth client setting, choose **Use your own OAuth client**: client ID `claude-ai`,
secret left blank, since it is a public client that relies on PKCE. **Register automatically**
will not work in this setup, and neither will **Use Claude's published identity**, since the
server does not support Client ID Metadata Documents.

Claude cannot change a connector's authentication settings afterwards; remove it and add it
again.

The server has to be reachable from Anthropic's network (`160.79.104.0/21`), including its discovery
documents, so do not put an IP allowlist or a bot filter in front of it that blocks that range.

## Operate it

**Rotate the signing key.** Put the new key first and keep the old one listed until the
tokens it signed have expired (`access_token_ttl`), then remove it. The JWKS lists every
key. A reload applies it.

**Rotate the sealing key.** Same idea: new key first, keep the old one for as long as
anything sealed with it can still be valid (`refresh_absolute_lifetime`). Removing a
sealing key logs out everyone whose refresh token it sealed.

**Offboard someone.** Add their subject to `denylist.subjects`. It takes effect on the
next request: their access token stops working, their refresh token is refused, and they
cannot log in again. The list hot-reloads.

**Group changes** reach a token at the next login, not at refresh: the groups are a
snapshot from the login, and a session ends `refresh_absolute_lifetime` after it started.

## Security notes

- Tokens are bearer tokens. Anyone holding one can use it until it expires; keep
  `access_token_ttl` short.
- An authorization code is not single use. It lasts `code_ttl` and is useless without the
  PKCE verifier only the client has.
- A refresh token is not single use either. Each refresh issues a new one, but the old one
  keeps working until `refresh_absolute_lifetime` is over, and a reused token is not detected.
  A stolen refresh token therefore lasts that long: keep the lifetime as short as people can
  bear, and use the denylist to cut someone off.
- There is no per-token revocation; the denylist works by subject. Replacing every
  sealing key signs everyone out.
- A token the server issued is not accepted as a login, so a stolen access token cannot
  be traded for a fresh refresh token.
- The login request and the login result travel in URLs as encrypted values, so an
  ingress or load balancer in front of the proxy will log them. They are short lived.
- Use `https` for `sp_base_url` outside local testing. `http` is for loopback only.

## Routes

All served by the proxy, under `<sp_base_url>/_tap/oauth`, never forwarded to the
backend, and not subject to the ACL:

| Path | Purpose |
|---|---|
| `/authorize` | Starts a login (authorization code with PKCE `S256`) |
| `/login` | Runs the proxy's own login, then hands the result back |
| `/authorize/callback` | Turns a finished login into an authorization code |
| `/token` | Exchanges a code or a refresh token |
| `/register` | Client registration, only with `dynamic_registration` on |
| `/jwks.json` | The public signing keys |
| `/.well-known/openid-configuration` | Discovery document |
| `/protected-resource` | Protected resource metadata for `mcp_url` |
