pub mod config;
mod crypto;
mod oauth;
mod proxy;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method},
    routing::{any, get, post},
};
use tower_http::cors::{AllowHeaders, CorsLayer};

use config::Config;
use crypto::Sealer;

struct App {
    config: Config,
    sealer: Sealer,
    http: reqwest::Client,
    pending: Mutex<HashMap<String, oauth::Pending>>,
    codes: Mutex<HashMap<String, oauth::Code>>,
}

/// Build one proxy for one upstream. No MCP SDK or message parsing is needed.
pub fn router(config: Config) -> Result<Router> {
    config.validate()?;
    let sealer = Sealer::load(
        &config.token_key_file,
        format!("{}\n{}", config.resource(), config.upstream_url),
    )?;
    let origins = config
        .origins()
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;
    let state = Arc::new(App {
        config,
        sealer,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?,
        pending: Mutex::new(HashMap::new()),
        codes: Mutex::new(HashMap::new()),
    });
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth::resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(oauth::server_metadata),
        )
        .route("/oauth/register", post(oauth::register))
        .route(
            "/oauth/authorize",
            get(oauth::authorize).post(oauth::consent),
        )
        .route("/oauth/token", post(oauth::token))
        .route("/mcp", any(proxy::forward))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers(AllowHeaders::mirror_request())
                .expose_headers([
                    "www-authenticate".parse::<axum::http::HeaderName>()?,
                    "mcp-session-id".parse()?,
                    "mcp-protocol-version".parse()?,
                ]),
        )
        .with_state(state))
}
