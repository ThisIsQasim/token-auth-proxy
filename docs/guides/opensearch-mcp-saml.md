# Example: OpenSearch MCP with SAML login

Put the proxy in front of the OpenSearch MCP endpoint when Dashboards already signs
people in with SAML. MCP clients such as Claude Code log in through the same IdP, and each
tool call runs in OpenSearch as the same user, with the same roles, as that person's
Dashboards session.

```text
Dashboards ──SAML──────────────────────────────┐
                                               ├──> IdP
Claude Code ──OAuth──> token-auth-proxy ──SAML─┘
                              │
                              └── Bearer token ──> OpenSearch /_plugins/_ml/mcp
```

The proxy signs people in with SAML and issues its own short-lived tokens, because a SAML
login gives a client nothing it can refresh. OpenSearch verifies those tokens against the
proxy's public keys. The [MCP OAuth server guide](mcp-oauth-server.md) explains each field used here.

This example assumes:

| | |
|---|---|
| Proxy | `https://os-mcp.example.com` |
| Dashboards | `https://dashboards.example.com` |
| IdP entity ID | `https://idp.example.com/saml/opensearch` |
| IdP metadata | `https://idp.example.com/saml/opensearch/metadata` |
| Attribute holding the person's groups | `Roles` |
| Group allowed to use MCP | `os-mcp-readers` |

## 1. Match the existing SAML domain

Find `saml_auth_domain` in your OpenSearch security `config.yml`. Two of its settings decide
what goes in the proxy's tokens:

| OpenSearch SAML setting | Proxy setting | Value in this example |
|---|---|---|
| `roles_key` | `outbound.token.claims.groups` | `Roles` |
| `subject_key` | `outbound.token.claims.subject` | Not set, so both use the SAML NameID |

Both must name the same attribute on each side, and on the IdP as well. A name that does not
match raises no error: the person signs in and simply has no roles. If your domain sets
`subject_key`, set `claims.subject` to the same attribute.

## 2. Register the proxy with the IdP

The proxy is a second service provider, so give it its own application next to the Dashboards
one, because its ACS URL differs:

| | |
|---|---|
| ACS URL | `https://os-mcp.example.com/_tap/saml/acs` |
| SP entity ID | `https://os-mcp.example.com/saml/metadata` |
| Binding | HTTP-POST |
| NameID | The same value the Dashboards application sends |
| Attributes | The same `Roles` attribute the Dashboards application sends |

The proxy does not sign its `AuthnRequest`s, so leave that requirement off.

## 3. Create the keys

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.pem
openssl rand -base64 32 > seal.key
openssl rand -base64 32 > session.key
```

Mount `signing.pem` and `seal.key` at `/keys`, and expose the contents of `session.key` as
the environment variable `CORP_SSO_SESSION_KEY`.

## 4. Configure the proxy

```yaml
listen_addr: :8080

target: https://opensearch:9200
target_ca_cert: ${file:/keys/opensearch-ca.crt}

inbound:
  auth:
    saml:
      name: corp-sso
      issuer: https://idp.example.com/saml/opensearch
      idp_metadata_url: https://idp.example.com/saml/opensearch/metadata
      sp_base_url: https://os-mcp.example.com
      sp_entity_id: https://os-mcp.example.com/saml/metadata
      session_cookie: corp_sso_session
      session_signing_key_env: CORP_SSO_SESSION_KEY
  oauth_server:
    sp_base_url: https://os-mcp.example.com
    mcp_url: https://os-mcp.example.com/_plugins/_ml/mcp
    sealing_keys:
      - ${file:/keys/seal.key}
    dynamic_registration:
      enabled: true
      redirect_uris:
        - https://claude.ai/api/mcp/auth_callback

outbound:
  token:
    signing_keys:
      - kid: "2026-11"
        private_key: ${file:/keys/signing.pem}
    claims:
      groups: Roles

acl:
  - principals:
      - mode: jwt
        source: tap-oauth
    paths:
      - /_plugins/_ml/mcp
```

`issuer` must equal the `entityID` in the IdP's metadata. The ACL lets anyone who signs in
reach the MCP endpoint and nothing else, including a browser holding a SAML session. What
they can do there is decided by OpenSearch.

## 5. Add an authentication domain to OpenSearch

Add the proxy as an `openid` domain and leave the SAML domain as it is, except that it must
stay last. It has `challenge: true`, so it has to come after the domains that do not
challenge.

```yaml
config:
  dynamic:
    authc:
      basic_internal_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: internal
      mcp_openid_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 1
        http_authenticator:
          type: openid
          challenge: false
          config:
            subject_key: sub
            roles_key: groups
            required_audience: https://os-mcp.example.com/_plugins/_ml/mcp
            openid_connect_url: https://os-mcp.example.com/_tap/oauth/.well-known/openid-configuration
        authentication_backend:
          type: noop
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 2
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_url: https://idp.example.com/saml/opensearch/metadata
              entity_id: https://idp.example.com/saml/opensearch
            sp:
              entity_id: opensearch-saml
            kibana_url: https://dashboards.example.com/
            roles_key: Roles
            exchange_key: <your existing exchange_key>
        authentication_backend:
          type: noop
```

`subject_key` and `roles_key` in the new domain stay `sub` and `groups`: those are the
claims of the proxy's token, whatever the SAML attributes are called. OpenSearch must be able
to reach `openid_connect_url`.

## 6. Give the group access to MCP

A role needs the MCP permission as well as access to the data:

```yaml
mcp_reader:
  reserved: false
  cluster_permissions:
    - cluster:admin/opensearch/ml/mcp/server
  index_permissions:
    - index_patterns:
        - logs-*
      allowed_actions:
        - read
```

```yaml
mcp_reader:
  reserved: false
  backend_roles:
    - os-mcp-readers
```

Check which roles a group name already maps to. The demo security configuration maps a
backend role called `readall` to a role that reads every index, so a group with that name
gets far more than `mcp_reader`.

Then turn the MCP server on and register the tools it should offer:

```sh
curl -X PUT https://opensearch:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"persistent": {"plugins.ml_commons.mcp_server_enabled": true}}'

curl -X POST https://opensearch:9200/_plugins/_ml/mcp/tools/_register \
  -H 'Content-Type: application/json' \
  -d '{"tools": [{"type": "SearchIndexTool", "name": "SearchOsIndex"}]}'
```

Both need an admin credential.

## 7. Connect and check

```sh
claude mcp add --transport http os https://os-mcp.example.com/_plugins/_ml/mcp
claude mcp login os
```

The browser opens at the IdP. After the login, the proxy logs `oauth login` with
`"mode":"saml"` and the person's subject.

| Person | Result |
|---|---|
| In `os-mcp-readers`, searching `logs-*` | The tool returns the documents |
| In `os-mcp-readers`, searching another index | `no permissions for [indices:data/read/search]` |
| Not in `os-mcp-readers` | Signs in, then every MCP call fails with `no permissions for [cluster:admin/opensearch/ml/mcp/server]` |

To compare the two logins, read `/_plugins/_security/authinfo` from a Dashboards session and
with an access token sent straight to OpenSearch. `user_name` and `backend_roles` should be
identical.

If `backend_roles` is empty for someone who has groups, the attribute name differs somewhere:
decode the `SAMLResponse` the browser posts to the ACS URL and compare the attribute's `Name`
with `roles_key` and `claims.groups`. The Dashboards and proxy applications can differ here,
so check each one.
