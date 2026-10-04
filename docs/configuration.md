# Configuration and deployment

Configuration is a TOML file. Run `oauth-to-key-mcp-proxy --config /path/to/config.toml`; without arguments it reads `config.toml` in the current directory. Restart the process after changing the file. Unknown options are rejected so spelling mistakes cannot silently alter behavior.

| Option | Default | Meaning |
| --- | --- | --- |
| `public_url` | Required | Client-facing HTTPS origin, without a path, query, credentials, or fragment. HTTP is allowed for loopback development. |
| `upstream_url` | Required | Exact HTTP or HTTPS Streamable HTTP endpoint. Its path and configured query are retained. URL credentials and fragments are rejected. |
| `bind` | `"0.0.0.0:8080"` | Socket address on which the process listens. |
| `token_key_file` | `"data/token.key"` | Persistent, automatically generated 32-byte encryption key. The container example uses `/data/token.key`. |
| `name` | `"MCP server"` | Label on the authorization page and protected-resource metadata. |
| `allowed_origins` | `[]` | Additional exact browser origins allowed to call the proxy. Its public origin is always allowed. Entries have no trailing slash. |
| `upstream_header_timeout_seconds` | `300` | Maximum time to send a request and receive upstream response headers. Does not time out an active response body or SSE stream. |
| `oauth.client_id` | Unset | Optional pre-registered client whose OAuth secret supplies the upstream API token. |
| `oauth.redirect_uris` | `[]` | Exact callbacks for that pre-registered client. Required when `client_id` is set. |

For example:

```toml
public_url = "https://mcp.example.com"
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

Callbacks must use HTTPS or loopback HTTP, contain no credentials or fragments, and match exactly. Wildcards, prefix matching, and custom URI schemes are unsupported. Each client may register up to five callbacks of at most 512 bytes each. OAuth request bodies are limited to 32 KiB; raw API tokens must have 1–4096 visible ASCII bytes and no whitespace.

## Container deployment

The image runs as UID/GID `65532`, includes TLS trust roots, and has no shell or package manager. It needs write access only to the directory containing `token_key_file`. A fresh named Docker volume inherits the image's `/data` ownership. If you use a host directory instead, make it writable by UID `65532` and apply any required SELinux label.

The example Compose file binds port 8080 to loopback for a host reverse proxy. To reach a separate MCP container, attach both containers to the same Docker network and use its service name in `upstream_url`. Inside the proxy container, `localhost` refers to the proxy itself.

Expose the whole public origin through HTTPS. Path-prefix hosting is intentionally unsupported. Do not buffer SSE responses or apply a short idle timeout to them. `/healthz` returns `200` and `ok` when the process is running; it does not send requests to the upstream or verify an API token.

Run one process/container per configured endpoint. In-progress browser forms and authorization codes live in memory, so multiple replicas behind a load balancer require sticky routing; this utility is intended for one lightweight instance per MCP.

## Credentials and restarts

The proxy keeps no API-token database. Access tokens contain encrypted API keys, which the proxy decrypts only to authenticate upstream requests. Dynamic client registrations are also encrypted into opaque client IDs. Both remain valid after a restart when the same key file and endpoint URLs are retained. Pending browser forms and unexchanged authorization codes must be retried after a restart.

Access tokens have the same lifetime as the upstream API key. There is no independent expiry or refresh grant; the token response omits `expires_in`. An upstream `401` triggers the proxy's OAuth discovery challenge so the client can reconnect with a replacement key. Revoke an individual connection by revoking its upstream key. Deleting or rotating `token_key_file` disconnects **all** connections and invalidates dynamic registrations.

Treat the encryption key and OAuth tokens as credentials. Back up the data volume securely, keep tokens out of access logs, and use HTTPS to any remote upstream. Changing `public_url` or `upstream_url` invalidates issued tokens and dynamic registrations because the encryption context binds both endpoints.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Client cannot discover OAuth | Route `/.well-known/*`, `/oauth/*`, and `/mcp` to the same instance; verify `public_url`. |
| `redirect_uri is not registered` | Copy the exact callback URL, including path, query, and any loopback port. |
| `S256 PKCE is required` | Use a client supporting the OAuth authorization-code flow with S256 PKCE. |
| Authorization form expired | Restart the linking flow; forms last ten minutes and codes last two minutes. |
| MCP returns `401` | Check the upstream API token and its validity. Paste only the raw token. |
| Browser receives `403` | Add the browser client's exact origin to `allowed_origins` and restart. |
| `502` or `504` | Check Docker networking, TLS, the upstream endpoint URL, and the response-header timeout. |
| Connections stop working after an update | Check that the original data volume and endpoint URLs were retained. |
