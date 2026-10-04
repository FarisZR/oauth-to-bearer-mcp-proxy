use std::path::PathBuf;

use anyhow::{Result, bail};
use oauth_to_key_mcp_proxy::{config::Config, router};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = match args.next().as_deref() {
        None => PathBuf::from("config.toml"),
        Some("--config" | "-c") => PathBuf::from(
            args.next()
                .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?,
        ),
        Some("--help" | "-h") => {
            println!(
                "oauth-to-key-mcp-proxy [--config PATH]\n\nDefault configuration: config.toml\nOne OAuth facade for one bearer-authenticated HTTP MCP server."
            );
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("oauth-to-key-mcp-proxy {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(_) => bail!("unknown argument; use --help"),
    };
    if args.next().is_some() {
        bail!("unexpected argument; use --help");
    }
    let config = Config::load(&path)?;
    let bind = config.bind;
    let app = router(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "oauth-to-key-mcp-proxy listening on {}",
        listener.local_addr()?
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).expect("cannot install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
