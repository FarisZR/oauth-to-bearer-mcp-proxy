# Implementation

The proxy adds an OAuth authorization-code surface to one HTTP endpoint. It does not implement an identity provider or understand MCP JSON-RPC. The upstream API key remains the authority for all permissions.

## Request flow

```mermaid
sequenceDiagram
    participant Client as MCP client
    participant User as Browser
    participant Proxy
    participant Upstream as Bearer MCP server
    Client->>Proxy: /mcp without a token
    Proxy-->>Client: 401 + resource_metadata challenge
    Client->>Proxy: Discover resource and authorization metadata
    Client->>Proxy: Register client (or use pre-registered ID)
    Client->>User: Open authorization URL with S256 challenge
    User->>Proxy: Confirm connection; supply API token if needed
    Proxy-->>Client: Callback with single-use code, state, and issuer
    Client->>Proxy: Exchange code + verifier + client authentication
    Proxy-->>Client: Opaque OAuth access token
    Client->>Proxy: MCP request + Bearer access token
    Proxy->>Upstream: Same MCP request + Bearer API token
    Upstream-->>Proxy: JSON or streaming SSE response
    Proxy-->>Client: Same response body and MCP metadata
```

For a pre-registered client, the API key arrives as `client_secret` at the token endpoint rather than through the browser form. The proxy wraps the supplied key without making a speculative upstream request; the first MCP request determines whether the upstream accepts it.

For a dynamically registered client, confidential-client secrets are random, ordinary OAuth client credentials. The API key arrives through the browser form and is bound to the subsequently issued code. Public clients use `token_endpoint_auth_method = "none"`. Different clients can connect with different upstream keys.

## OAuth surface

| Endpoint | Behavior |
| --- | --- |
| `GET /.well-known/oauth-protected-resource[/mcp]` | Resource metadata advertising this `/mcp` endpoint and its authorization server. |
| `GET /.well-known/oauth-authorization-server` | Authorization-code, registration, token-authentication, and S256 metadata. |
| `GET /.well-known/openid-configuration` | The same authorization-server metadata for discovery compatibility; no OpenID identity tokens are issued. |
| `POST /oauth/register` | RFC 7591 registration for public, Basic, or POST authenticated clients. |
| `GET /oauth/authorize` | Validate client, callback, resource, and PKCE; display the connection form. |
| `POST /oauth/authorize` | Check browser cookie and Origin; grant a code or redirect with `access_denied`. |
| `POST /oauth/token` | Authenticate the client and exchange a code with its verifier for an opaque bearer token. |
| `GET/POST/DELETE /mcp` | Decrypt a proxy-issued token and stream the request to the configured upstream. |
| `GET /healthz` | Process liveness only. |

Resource indicators must match the configured public `/mcp` URL when supplied. Omitting `resource` is accepted for older clients. Callbacks match registered URI strings exactly. Authorization responses preserve `state`, include `iss`, and retain unrelated registered callback query parameters.

S256 PKCE is required for all clients. Codes are random, single-use, bound to client ID, redirect URI, and challenge, and expire after 120 seconds. Browser forms expire after 600 seconds and require an HttpOnly, SameSite cookie. Consent cannot be submitted from another Origin. Each in-memory collection is bounded at 1,024 entries and expired entries are pruned on use. Successful code consumption is atomic under a mutex.

OAuth responses carrying credentials or authorization state use `Cache-Control: no-store`. The authorization page escapes displayed values, has no JavaScript or external assets, and applies a restrictive CSP. API keys never appear in authorization URLs, callback URLs, configuration, or application logs.

This is a deliberately small OAuth subset: authorization codes, pre-registration or dynamic registration, and bearer access tokens. It provides no refresh grant, identity tokens, Client ID Metadata Document fetching, local scope enforcement, or per-token revocation endpoint. Requested scope labels are echoed; the upstream key determines actual permissions. Dynamic registration requests including `refresh_token` are narrowed to `authorization_code` in the returned metadata. Clients requiring other grants or registration mechanisms need a different authorization server.

## Stateless credentials

`crypto.rs` uses XChaCha20-Poly1305 authenticated encryption with an OS-generated 256-bit key and a fresh 192-bit nonce per object. The binary key file is created once with Unix mode `0600`; existing malformed keys cause startup to fail rather than silently invalidating clients.

Opaque tokens encode `nonce || ciphertext || authentication tag` as unpadded base64url. Associated data separates the `access` and `client` purposes and binds the public resource URL and exact upstream URL. An access token cannot be used as a client registration or on a different proxy configuration, even if the encryption key is reused.

Dynamic registrations encrypt callback metadata, the display name, the selected authentication method, and any generated client secret into the `dcr_` client ID. No registration table, disk updates, database, or external service is needed. Access tokens encrypt only the API key; they have no proxy-specific expiry. The key's upstream expiry and revocation still apply.

## HTTP forwarding

`proxy.rs` streams the Axum request body into Reqwest and its response byte stream back into Axum. It does not buffer, parse, rewrite, retry, or reinitialize MCP messages. Session identifiers, protocol headers, event IDs, content types, payload bytes, and upstream status codes are retained. The client's query is appended to any configured upstream query. Tokens in `access_token` query parameters are rejected.

Transport header changes are limited to the bridge: regenerate Host for the upstream, replace Authorization, remove hop-by-hop headers and any names nominated by Connection, remove cookies and forwarding headers, and translate an allowed client Origin to the upstream origin. Response cookies are stripped; upstream `401` challenges are replaced with the proxy's protected-resource discovery challenge. CORS allows the public origin plus configured browser origins and exposes MCP session and discovery headers.

Reqwest follows no redirects, so the API key cannot be sent to a redirect destination. An upstream redirect is returned as received; configure its final MCP URL to avoid redirecting clients outside the proxy. Redirects, errors, and response bodies may contain upstream information; this utility makes authentication transparent to the client protocol, not a mechanism for concealing an upstream's own content.

The request/header deadline defaults to 300 seconds; response streams have no total deadline. TLS validation remains enabled. Network failures produce a generic `502`, and the header deadline produces `504`; underlying errors are not logged with potentially sensitive URLs. The binary handles SIGINT and SIGTERM for graceful shutdown.

## References

The wire behavior follows the applicable portions of [MCP authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization), [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), and [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207). The facade idea is inspired by [Agent Box MCP](https://github.com/FarisZR/agentbox-mcp); this proxy forwards external HTTP servers rather than implementing their tools.
