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

The table shows paths for an origin-only `public_url`. With a base path, all application endpoints move under that path. For `/services/one`, MCP is `/services/one/mcp` and authorization is `/services/one/oauth/authorize`. Form actions and browser cookie paths include the prefix; Origin validation and CORS use the URL's origin without its path.

Canonical discovery follows RFC 8414 and RFC 9728: insert the well-known segment between the origin and the issuer/resource path. This gives `/.well-known/oauth-authorization-server/services/one` and `/.well-known/oauth-protected-resource/services/one/mcp`. The `401` challenge advertises the latter, and metadata advertises the exact issuer and resource. Issuer-relative discovery aliases also work. Prefixed instances expose no origin-wide discovery route, so multiple instances can share a hostname. Tokens and registrations are bound to the resource URL, including its prefix.

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

S256 PKCE is required for all clients. Codes are random, single-use, bound to client ID, redirect URI, and challenge, and expire after 120 seconds. Successful code consumption is atomic under a mutex.

Browser forms carry an authenticated, encrypted `consent` ticket containing the validated request, a browser nonce, and a 600-second expiry. Opening a page allocates no shared pending state. Submission requires the nonce's HttpOnly, SameSite cookie and the same Origin; the callback is checked against the current client allowlist again. Expired, tampered, cross-instance, and wrong-purpose tickets are rejected. A form can be retried until expiry; issued codes remain single-use.

Code storage has a 1,024-entry defensive cap and expired entries are pruned on use. A token bucket inside the same mutex permits a burst of 32 codes and replenishes two per second across all client IDs and both key-entry modes. At most 32 + 2 × 120 = 272 codes can be issued in a code lifetime, so storage exhaustion cannot be reached by accumulating unexchanged codes. A compile-time assertion maintains this invariant. Rejected issuance returns `429` with a one-second retry hint, without invalidating the consent form; exchanges and established MCP sessions do not consume issuance credit.

OAuth responses carrying credentials or authorization state use `Cache-Control: no-store`. The authorization page escapes displayed values, has no JavaScript or external assets, and applies a restrictive CSP. API keys never appear in authorization URLs, callback URLs, configuration, or application logs.

This is a deliberately small OAuth subset: authorization codes, pre-registration or dynamic registration, and bearer access tokens. It provides no refresh grant, identity tokens, Client ID Metadata Document fetching, local scope enforcement, or per-token revocation endpoint. Requested scope labels are echoed; the upstream key determines actual permissions. Dynamic registration requests including `refresh_token` are narrowed to `authorization_code` in the returned metadata. Clients requiring other grants or registration mechanisms need a different authorization server.

## Stateless credentials

`crypto.rs` uses XChaCha20-Poly1305 authenticated encryption with an OS-generated 256-bit key and a fresh 192-bit nonce per object. The binary key file is created once with Unix mode `0600`; existing malformed keys cause startup to fail rather than silently invalidating clients.

Opaque tokens encode `nonce || ciphertext || authentication tag` as unpadded base64url. Associated data separates the `access`, `client`, and `consent` purposes and binds the public resource URL and exact upstream URL. An access token cannot be used as a client registration or on a different proxy configuration, even if the encryption key is reused.

Dynamic registrations encrypt callback metadata, the display name, the selected authentication method, and any generated client secret into the `dcr_` client ID. No registration table, disk updates, database, or external service is needed. Access tokens encrypt only the API key; they have no proxy-specific expiry. The key's upstream expiry and revocation still apply.

## HTTP forwarding

`proxy.rs` streams the Axum request body into Reqwest and its response byte stream back into Axum. It does not buffer, parse, rewrite, retry, or reinitialize MCP messages. Session identifiers, protocol headers, event IDs, content types, payload bytes, and upstream status codes are retained. The client's query is appended to any configured upstream query. Tokens in `access_token` query parameters are rejected.

Transport header changes are limited to the bridge: regenerate Host for the upstream, replace Authorization, remove hop-by-hop headers and any names nominated by Connection, remove cookies and forwarding headers, and translate an allowed client Origin to the upstream origin. Response cookies are stripped; upstream `401` challenges are replaced with the proxy's protected-resource discovery challenge. CORS allows the public origin plus configured browser origins and exposes MCP session and discovery headers.

Reqwest follows no redirects, so the API key cannot be sent to a redirect destination. An upstream redirect is returned as received; configure its final MCP URL to avoid redirecting clients outside the proxy. Redirects, errors, and response bodies may contain upstream information; this utility makes authentication transparent to the client protocol, not a mechanism for concealing an upstream's own content.

The upstream request/header deadline defaults to 300 seconds; response streams have no total deadline. TLS validation remains enabled. Network failures produce a generic `502`, and the upstream header deadline produces `504`; underlying errors are not logged with potentially sensitive URLs. The binary handles SIGINT and SIGTERM for graceful shutdown.

`server.rs` admits at most 64 inbound sockets before spawning connection tasks and immediately closes excess sockets. It reaps completed tasks even under continuous accepts. Hyper's HTTP/1 parser has a 10-second header deadline and a 32 KiB buffer limit. The HTTPS reverse proxy can expose HTTP/2 to clients while speaking HTTP/1 to this process, as with the original Axum server.

Request admission uses a 32-permit semaphore and rejects overload with `503` and `Retry-After: 1`. A body wrapper owns each permit until the response ends, errors, or is dropped, so SSE remains counted after headers are sent and disconnects release capacity. OAuth POST handlers have a 10-second deadline covering JSON/Form extraction and a 64 KiB body limit. Incomplete fixed-length or chunked bodies receive `408` and close. The byte limit accommodates serialized consent tickets at the existing state/key size limits; MCP bodies remain streamed. These defaults are configurable through `[limits]`. No inbound timeout imposes a total MCP stream lifetime.

## References

The wire behavior follows the applicable portions of [MCP authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization), [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), and [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207). The facade idea is inspired by [Agent Box MCP](https://github.com/FarisZR/agentbox-mcp); this proxy forwards external HTTP servers rather than implementing their tools.
