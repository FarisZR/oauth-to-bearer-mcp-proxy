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
    let mut routes = Router::new()
        .route(&config.endpoint_path("/healthz"), get(|| async { "ok\n" }))
        .route(
            &config.endpoint_path("/.well-known/oauth-protected-resource"),
            get(oauth::resource_metadata),
        )
        .route(
            &config.resource_metadata_path(),
            get(oauth::resource_metadata),
        )
        .route(&config.server_metadata_path(), get(oauth::server_metadata))
        .route(
            &config.endpoint_path("/.well-known/openid-configuration"),
            get(oauth::server_metadata),
        )
        .route(
            &config.endpoint_path("/oauth/register"),
            post(oauth::register),
        )
        .route(
            &config.endpoint_path("/oauth/authorize"),
            get(oauth::authorize).post(oauth::consent),
        )
        .route(&config.endpoint_path("/oauth/token"), post(oauth::token))
        .route(&config.endpoint_path("/mcp"), any(proxy::forward));
    if !config.prefix().is_empty() {
        // Also support clients using issuer-relative discovery. The canonical
        // RFC 8414 / RFC 9728 URLs above insert .well-known before the path.
        routes = routes
            .route(
                &config.endpoint_path("/.well-known/oauth-authorization-server"),
                get(oauth::server_metadata),
            )
            .route(
                &config.endpoint_path("/.well-known/oauth-protected-resource/mcp"),
                get(oauth::resource_metadata),
            )
            .route(
                &format!("/.well-known/openid-configuration{}", config.prefix()),
                get(oauth::server_metadata),
            );
    }
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
    Ok(routes
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
