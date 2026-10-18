# Browser login with OIDC

Put a browser login in front of an app using any OpenID Provider. The
proxy runs the authorization code flow, keeps the ID token in a cookie,
and verifies it on every request like any other JWT.

## Configure the IdP

Create an OIDC client for the proxy and register the redirect URI
`<sp_base_url><callback_path>`, for example
`https://proxy.example.com/oidc/callback`.

- **Confidential client**: the IdP gives you a client secret.
- **Public client**: no secret; the IdP must allow PKCE (S256).

## Configure the proxy

```yaml
target: http://app:8080
inbound:
  auth:
    jwt:
      - name: authentik
        issuer: https://auth.example.com/application/o/proxy/
        oidc_discovery_url: https://auth.example.com/application/o/proxy/.well-known/openid-configuration
        login:
          label: Authentik
          client_id: my-proxy
          client_secret: ${env:PROXY_OIDC_CLIENT_SECRET}
          sp_base_url: https://proxy.example.com
```

**`login` fields** (all per source):

| Field | Default | Meaning |
|---|---|---|
| `client_id` | required | OAuth client ID; also the default `audiences` (if you set `audiences` it must include it) |
| `client_secret` | none | Makes it a confidential client. Use `${env:NAME}` or `${file:PATH}`. Omit for a public client |
| `token_auth_method` | `client_secret_basic` | `client_secret_basic` or `client_secret_post`; only with a secret |
| `sp_base_url` | required | The proxy's own origin as the browser sees it |
| `callback_path` | `/oidc/callback` | Register `sp_base_url + callback_path` as the redirect URI |
| `scopes` | `openid profile email` | Requested scopes; must include `openid` |
| `cookie_name` | `tap_id_token` | The ID token cookie |
| `label` | the source name | Button text on the login picker |
| `refresh` | `false` | Renew the session with a refresh token (see below) |
| `refresh_max_age` | `720h` | Lifetime of the refresh cookie; only with `refresh` |

Drop `client_secret` for a public client. Reference the secret with
`${env:NAME}` or `${file:PATH}` rather than writing it in the file.

`audiences` defaults to the `client_id`. Add an `acl` to restrict who
gets in; it matches the ID token's claims:

```yaml
acl:
  - principals:
      - mode: jwt
        source: authentik
        claims:
          groups: admins
```

## Scopes and claims

`login.scopes` defaults to `openid profile email`. An ACL can only match
claims that are in the ID token, and many IdPs include `groups` (or
custom claims) only when the matching scope is requested:

```yaml
login:
  scopes: [openid, profile, email, groups]
```

## What users see

1. A browser with no cookie asks for `/dashboards`.
2. The proxy redirects it to the IdP, which signs the user in.
3. The IdP redirects to `/oidc/callback`; the proxy verifies the token,
   sets the `tap_id_token` cookie and sends the browser to `/dashboards`.

The session ends when the ID token expires, and the user signs in again,
unless refresh is on (below). If your IdP issues large tokens (many groups), keep
the token under about 4KB or trim its claims at the IdP.

## Refresh tokens

With `login.refresh: true` the proxy keeps the user signed in past the ID
token's expiry by redeeming a refresh token:

```yaml
login:
  scopes: [openid, profile, email, offline_access]
  refresh: true
  refresh_max_age: 168h # optional, default 720h
```

The IdP must issue refresh tokens to this client; `offline_access` is the
usual way to ask for one, and is not added for you because some IdPs
reject it. The refresh token lives in a second cookie and is never sent
to your app. If the IdP revokes it, the user signs in again; if the IdP
is down, requests get a `503` and the user stays signed in.

## Combining with SAML or Basic

**More than one source.** Each source with a `login` block is a
separate login method with its own client, scopes and cookies, and
gets its own button on the picker. Their `callback_path` and
`cookie_name` values must differ (validation rejects duplicates):

```yaml
inbound:
  auth:
    jwt:
      - name: authentik
        issuer: https://auth.example.com/application/o/proxy/
        oidc_discovery_url: https://auth.example.com/application/o/proxy/.well-known/openid-configuration
        login:
          client_id: proxy-a
          client_secret: ${env:AUTHENTIK_SECRET}
          sp_base_url: https://proxy.example.com
          scopes: [openid, profile, email, groups]
      - name: google
        issuer: https://accounts.google.com
        oidc_discovery_url: https://accounts.google.com/.well-known/openid-configuration
        login:
          client_id: proxy-b
          sp_base_url: https://proxy.example.com
          callback_path: /oidc/google/callback
          cookie_name: tap_id_token_google
          scopes: [openid, email]
```


With more than one interactive method configured, a browser with no
credential sees a picker at `/_tap/login` with one button per method.
Basic answers with a `401` challenge so the browser asks for the
password. The choice is remembered in a cookie, so the picker only shows
the first time.

Requests that are not browser navigations (APIs, `curl`) never see the
picker: they get `401`, and bearer tokens keep working.

## Troubleshooting

- **`login session expired, try again`**: the state cookie was missing.
  Check that `sp_base_url` is the address the browser uses, and use
  `https` unless you are on localhost, since browsers drop `Secure`
  cookies on plain http.
- **`login failed` with `503`**: the proxy could not fetch the discovery
  document; see its logs for `login_unavailable`.
- **Token too large**: the log line names the size.

## Styling the picker

`inbound.auth.login_page.css` is appended after the built-in styles:

```yaml
inbound:
  auth:
    login_page:
      css: |
        :root { --accent: #0a7d4f; }
        .tap-login-title { letter-spacing: .02em; }
```

Override the custom properties `--bg`, `--fg`, `--card`, `--line`,
`--accent` and `--accent-fg`, or target `tap-login` (the card),
`tap-login-title` and `tap-login-method` (each button). To keep the
stylesheet in its own file, use `css: "${file:/etc/token-auth-proxy/login.css}"`.
