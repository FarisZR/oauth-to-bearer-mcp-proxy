# Configuration and deployment

Configuration is a TOML file. Run `oauth-to-key-mcp-proxy --config /path/to/config.toml`; without arguments it reads `config.toml` in the current directory. Restart the process after changing the file. Unknown options are rejected so spelling mistakes cannot silently alter behavior.

| Option | Default | Meaning |
| --- | --- | --- |
| `public_url` | Required | Client-facing HTTPS base URL, optionally including a path. No query, credentials, or fragment. HTTP is allowed for loopback development. |
| `upstream_url` | Required | Exact HTTP or HTTPS Streamable HTTP endpoint. Its path and configured query are retained. URL credentials and fragments are rejected. |
| `bind` | `"0.0.0.0:8080"` | Socket address on which the process listens. |
| `token_key_file` | `"data/token.key"` | Persistent, automatically generated 32-byte encryption key. The container example uses `/data/token.key`. |
| `name` | `"MCP server"` | Label on the authorization page and protected-resource metadata. |
| `allowed_origins` | `[]` | Additional exact browser origins allowed to call the proxy. Its public origin is always allowed. Entries have no trailing slash. |
| `upstream_header_timeout_seconds` | `300` | Maximum time to send a request and receive upstream response headers. Does not time out an active response body or SSE stream. |
| `oauth.client_id` | Unset | Optional pre-registered client whose OAuth secret supplies the upstream API token. |
| `oauth.redirect_uris` | `[]` | Exact callbacks for that pre-registered client. Required when `client_id` is set. |
| `limits.max_connections` | `64` | Maximum open inbound sockets, including idle and incomplete requests. Excess connections close immediately. |
| `limits.max_requests` | `32` | Maximum active requests, including response streams through EOF or disconnect. Excess requests return `503` with `Retry-After: 1`. |
| `limits.header_timeout_seconds` | `10` | Deadline for receiving complete HTTP request headers. |
| `limits.oauth_body_timeout_seconds` | `10` | Deadline for receiving and processing a complete OAuth POST body. Slow requests return `408` and close. Does not limit MCP response streams. |

For example:

```toml
public_url = "https://mcp.example.com/services/one"
upstream_url = "http://internal-mcp:9000/api/mcp?workspace=example"
bind = "0.0.0.0:8080"
token_key_file = "/data/token.key"
name = "Example MCP"
allowed_origins = ["https://my-agent.example.com"]
upstream_header_timeout_seconds = 300

[oauth]
client_id = "mcp-proxy"
redirect_uris = ["https://my-agent.example.com/oauth/callback"]
```

The pre-registered client is optional. Dynamic registration is always available for clients that discover `/oauth/register`. Dynamically registered clients enter the API token in the authorization page; their generated OAuth client secret, if any, authenticates the client and is separate from the API token. A pre-registered client enters the API token as its OAuth client secret instead.

Callbacks must use HTTPS or loopback HTTP, contain no credentials or fragments, and match exactly. Wildcards, prefix matching, and custom URI schemes are unsupported. Each client may register up to five callbacks of at most 512 bytes each. OAuth request bodies are limited to 64 KiB, including encrypted form tickets; raw API tokens must have 1–4096 visible ASCII bytes and no whitespace.

Inbound HTTP headers are limited to 32 KiB. Limits apply at the origin and at every configured prefix. Connection and request limits accept values from 1 to 4096; inbound deadlines accept 1 to 300 seconds. Override defaults only if needed:

```toml
[limits]
max_connections = 64
max_requests = 32
header_timeout_seconds = 10
oauth_body_timeout_seconds = 10
```

Opening authorization pages reserves no shared storage. Authorization-code issuance allows a burst of 32 codes, then two per second across the instance, including newly registered clients. Overload returns `429` with `Retry-After: 1`; the same consent form can be retried. Existing codes can still be exchanged and existing access tokens still work. This issuance budget is fixed so unexchanged codes cannot exhaust their shared storage during their two-minute lifetime.

## Container deployment

The image runs as UID/GID `65532`, includes TLS trust roots, and has no shell or package manager. It needs write access only to the directory containing `token_key_file`. A fresh named Docker volume inherits the image's `/data` ownership. If you use a host directory instead, make it writable by UID `65532` and apply any required SELinux label.

The example Compose file binds port 8080 to loopback for a host reverse proxy. To reach a separate MCP container, attach both containers to the same Docker network and use its service name in `upstream_url`. Inside the proxy container, `localhost` refers to the proxy itself.

Compose also caps the container at 128 MiB RAM, half a CPU, 64 processes/threads, and 1024 file descriptors. The PID cap leaves room for DNS resolver threads alongside the 32 active requests. The application limits bound sockets, requests, and OAuth state independently. Keep ingress connection/rate controls on the HTTPS reverse proxy for sustained public traffic floods; application limits cannot prevent network saturation.

Expose the configured base URL through HTTPS, preserving its path. Do not buffer SSE responses or apply a short idle timeout to them. `<base>/healthz` returns `200` and `ok` when the process is running; it does not send requests to the upstream or verify an API token.

### Shared-domain routing

For `public_url = "https://mcp.example.com/services/one"`, route these paths to this instance:

| Path | Purpose |
| --- | --- |
| `/services/one/*` | MCP, OAuth endpoints, health check, and issuer-relative discovery aliases. |
| `/.well-known/oauth-protected-resource/services/one/mcp` | RFC 9728 protected-resource discovery, advertised in the `401` challenge. |
| `/.well-known/oauth-authorization-server/services/one` | RFC 8414 authorization-server discovery. |
| `/.well-known/openid-configuration/services/one` | Additional discovery compatibility. |

These discovery URLs insert `/.well-known/` before the base path; forwarding only `/services/one/*` is insufficient. See the [Caddy example](../README.md#several-instances-on-one-domain). Preserve the full incoming path rather than stripping the prefix. Use separate Compose projects or service names, published ports, configuration files, and data volumes for each instance.

Paths may contain letters, digits, `/`, `-`, `.`, `_`, and `~`, up to 512 bytes, with no empty segments. A trailing slash is normalized away. Each prefix has a distinct issuer and resource, and neither claims origin-wide discovery routes. An origin-only base URL still uses `/mcp` and `/oauth/*`. `allowed_origins` contains origins such as `https://my-agent.example.com`, never base paths.

Run one process/container per configured endpoint. Authorization codes live in memory, so multiple replicas behind a load balancer require sticky routing; this utility is intended for one lightweight instance per MCP.

## Credentials and restarts

The proxy keeps no API-token database. Access tokens contain encrypted API keys, which the proxy decrypts only to authenticate upstream requests. Dynamic client registrations are also encrypted into opaque client IDs. Both remain valid after a restart when the same key file and endpoint URLs are retained. Browser forms carry encrypted, expiring tickets and survive a restart; their callbacks are rechecked against the current configuration when submitted. Unexchanged authorization codes must be retried after a restart.

Access tokens have the same lifetime as the upstream API key. There is no independent expiry or refresh grant; the token response omits `expires_in`. An upstream `401` triggers the proxy's OAuth discovery challenge so the client can reconnect with a replacement key. Revoke an individual connection by revoking its upstream key. Deleting or rotating `token_key_file` disconnects **all** connections and invalidates dynamic registrations.

Treat the encryption key and OAuth tokens as credentials. Back up the data volume securely, keep tokens out of access logs, and use HTTPS to any remote upstream. Changing `public_url` or `upstream_url` invalidates issued tokens and dynamic registrations because the encryption context binds both endpoints.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Client cannot discover OAuth | Route the base path and its path-specific discovery URLs to the same instance; verify `public_url` and preserve paths. |
| `redirect_uri is not registered` | Copy the exact callback URL, including path, query, and any loopback port. |
| `S256 PKCE is required` | Use a client supporting the OAuth authorization-code flow with S256 PKCE. |
| Authorization form expired | Restart the linking flow; forms last ten minutes and codes last two minutes. |
| MCP returns `401` | Check the upstream API token and its validity. Paste only the raw token. |
| Browser receives `403` | Add the browser client's exact origin to `allowed_origins` and restart. |
| `502` or `504` | Check Docker networking, TLS, the upstream endpoint URL, and the response-header timeout. |
| `408`, `429`, or `503` | Complete OAuth requests within the body deadline, retry after `Retry-After`, and check active connections/streams before increasing limits. |
| Connections stop working after an update | Check that the original data volume and endpoint URLs were retained. |
