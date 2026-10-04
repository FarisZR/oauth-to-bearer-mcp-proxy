# oauth-to-bearer-mcp-proxy

A small Rust proxy that gives a bearer-authenticated MCP server an OAuth interface. Use it when your agent client supports OAuth but has no way to enter a plain API token.

Deploy one instance per upstream MCP server. Clients connect through ordinary OAuth discovery and authorization; the proxy forwards their MCP requests with the upstream API token. Tool names, schemas, results, sessions, and SSE streams pass through unchanged.

## Run with Docker Compose

```sh
cp config.example.toml config.toml
```

Edit the two URLs and the server name:

```toml
public_url = "https://mcp.example.com/one"
upstream_url = "https://your-existing-mcp.example.com/mcp"
token_key_file = "/data/token.key"
name = "My MCP server"
```

Then start it:

```sh
docker compose up -d
curl http://127.0.0.1:8080/one/healthz
```

Put an HTTPS reverse proxy in front of port 8080. For example, a Caddy instance running on the same host can use:

```caddyfile
mcp.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Set `public_url` to the exact HTTPS base URL clients reach, including its path. The MCP endpoint is that URL plus `/mcp`. Preserve paths and streaming responses in your reverse proxy. On SELinux hosts, add `Z` to the config bind mount (`:ro,Z`).

The `proxy-data` volume holds an automatically generated encryption key. Keep this volume when updating or replacing the container so linked clients stay connected. API tokens do not go in the configuration file.

The defaults bound connections, active streams, and OAuth requests. Compose also caps memory, CPU, processes, and file descriptors. See [resource limits](docs/configuration.md) for tuning and retry behavior under load.

## Connect your agent client

Add `https://mcp.example.com/one/mcp` as the MCP server and select **OAuth**.

**Clients that register automatically:** leave the OAuth client ID and secret unset. When the authorization page opens, paste your upstream API token and click **Connect**.

**Clients with manual OAuth fields:** add this section to `config.toml`, using the exact callback URL provided by your client, and restart the container:

```toml
[oauth]
client_id = "mcp-proxy"
redirect_uris = ["https://your-client.example/oauth/callback"]
```

Use these values in the client:

| Field | Value |
| --- | --- |
| MCP URL | `https://mcp.example.com/one/mcp` |
| OAuth client ID | `mcp-proxy` |
| OAuth client secret | Your upstream API token, without `Bearer ` |
| Authorization URL, if requested | `https://mcp.example.com/one/oauth/authorize` |
| Token URL, if requested | `https://mcp.example.com/one/oauth/token` |
| Token endpoint authentication | `client_secret_post` or `client_secret_basic` |

Finish the normal OAuth linking flow. The client receives an opaque access token and needs no proxy-specific behavior. The upstream server decides what your API token can access and when it expires. Each connection can use a different API token.

The upstream must support **Streamable HTTP MCP** with `Authorization: Bearer <API token>`. This utility adds authentication compatibility; it does not translate stdio or legacy HTTP+SSE transports. Browser-based clients may need their origin added to `allowed_origins`; see [configuration](docs/configuration.md).

## Several instances on one domain

Give each instance its own base path, upstream, data volume, and host port. For example, `public_url = "https://mcp.example.com/one"` on port 8081 and `public_url = "https://mcp.example.com/two"` on port 8082 produce the client URLs `/one/mcp` and `/two/mcp`.

OAuth discovery also uses standard path-specific `/.well-known/` URLs. Route those alongside each base path. With Caddy:

```caddyfile
mcp.example.com {
    @one path /one/* /.well-known/oauth-authorization-server/one /.well-known/oauth-protected-resource/one/mcp /.well-known/openid-configuration/one
    handle @one {
        reverse_proxy 127.0.0.1:8081
    }

    @two path /two/* /.well-known/oauth-authorization-server/two /.well-known/oauth-protected-resource/two/mcp /.well-known/openid-configuration/two
    handle @two {
        reverse_proxy 127.0.0.1:8082
    }
}
```

Use `handle` to keep the path intact. Each instance has its own OAuth issuer, callbacks, and tokens. Nested paths such as `/services/one` work too. An origin without a path remains supported.

## Updates and local builds

GitHub Actions runs formatting, Clippy, tests, and Docker builds on pushes and pull requests. Successful pushes publish AMD64 and ARM64 images to `ghcr.io/fariszr/oauth-to-bearer-mcp-proxy`. `latest` follows `main`; branch, commit SHA, and `v*` tag images are also published.

```sh
docker compose pull
docker compose up -d
```

To build your own image:

```sh
docker build -t oauth-to-bearer-mcp-proxy .
```

To run without Docker, install Rust 1.91 or newer, choose a writable `token_key_file` such as `data/token.key`, and run:

```sh
cargo run --release --locked -- --config config.toml
```

For local development, `public_url = "http://127.0.0.1:8080"` is supported.

See [configuration and deployment](docs/configuration.md), [implementation](docs/implementation.md), and [development](docs/development.md) for details. Inspired by [Agent Box MCP's fake OAuth mode](https://github.com/FarisZR/agentbox-mcp).
