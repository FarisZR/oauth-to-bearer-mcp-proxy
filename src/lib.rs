pub mod config;
mod crypto;
mod oauth;
mod proxy;
mod server;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method},
    middleware,
    routing::{any, get, post},
};
use tower_http::cors::{AllowHeaders, CorsLayer};

use config::Config;
use crypto::Sealer;
pub use server::serve;
use tokio::sync::Semaphore;

struct App {
    config: Config,
    sealer: Sealer,
    http: reqwest::Client,
    codes: Mutex<oauth::Codes>,
    requests: Arc<Semaphore>,
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
        requests: Arc::new(Semaphore::new(config.limits.max_requests)),
        config,
        sealer,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?,
        codes: Mutex::new(oauth::Codes::new()),
    });
    Ok(routes
        // Stateless consent tickets include escaped OAuth state and client
        // metadata. All extraction is still bounded in bytes and time.
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), server::admit))
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
