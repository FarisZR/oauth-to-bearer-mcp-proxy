# Development

Use Rust 1.91 or newer. The lockfile is committed, and Docker and CI use Rust 1.91.1.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release --locked
docker build -t oauth-to-key-mcp-proxy .
```

To verify ordinary client interoperability on Linux, build the release image and run the official Python MCP SDK smoke test with [uv](https://docs.astral.sh/uv/):

```sh
docker build -t oauth-to-key-mcp-proxy:local .
uv run scripts/sdk-smoke.py
```

The script starts a real bearer-only MCP server, links an unmodified SDK OAuth client, lists and calls a tool, restarts the proxy, and checks both key-entry modes. It creates and cleans up its own temporary container, configuration, and data volume. Python and the SDK are development dependencies only.

`tests/end_to_end.rs` starts real HTTP listeners for the proxy and a recording upstream. Tests cover discovery, all three dynamically registered authentication methods, API keys supplied through pre-registered OAuth secrets, PKCE and callback/resource/client binding, browser CSRF, code replay, token tampering, restart continuity, and configuration validation. Forwarding tests check exact request/response bytes, large request bodies, header filtering, GET/POST/DELETE, queries, sessions, status codes, and an SSE response that stays open beyond the header timeout.

Source layout:

| File | Responsibility |
| --- | --- |
| `src/main.rs` | Configuration path, listener, shutdown signals. |
| `src/config.rs` | TOML schema and startup validation. |
| `src/crypto.rs` | Persistent key creation and authenticated token envelopes. |
| `src/oauth.rs` | Metadata, registration, consent, codes, PKCE, token exchange. |
| `src/proxy.rs` | Authentication translation and streaming HTTP forwarding. |
| `src/lib.rs` | Application state, route wiring, body limits, CORS. |

There is no MCP SDK dependency: the proxy does not interpret protocol messages. The binary uses one asynchronous event loop to keep each instance small. The Docker image uses a Debian builder and a nonroot distroless runtime with CA certificates. BuildKit caches dependency downloads and compiled artifacts by architecture.

The GitHub workflow validates every push and pull request, including the SDK smoke test, then builds AMD64/ARM64 containers on native runners. Successful push/manual runs publish architecture images and combine them into one multi-platform manifest. Registry login and image publication use the repository's `GITHUB_TOKEN` with `packages: write`; no registry secret is required. Action references are pinned to commit SHAs. Successful default-branch pushes publish `latest`; other pushes also get branch/tag and full commit-SHA tags. Pull requests build images without publishing.
