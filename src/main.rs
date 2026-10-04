use std::path::PathBuf;

use anyhow::{Result, bail};
use oauth_to_bearer_mcp_proxy::{config::Config, router, serve};

#[tokio::main(flavor = "current_thread")]
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
                "oauth-to-bearer-mcp-proxy [--config PATH]\n\nDefault configuration: config.toml\nOne OAuth facade for one bearer-authenticated HTTP MCP server."
            );
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("oauth-to-bearer-mcp-proxy {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(_) => bail!("unknown argument; use --help"),
    };
    if args.next().is_some() {
        bail!("unexpected argument; use --help");
    }
    let config = Config::load(&path)?;
    let bind = config.bind;
    let limits = config.limits.clone();
    let app = router(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "oauth-to-bearer-mcp-proxy listening on {}",
        listener.local_addr()?
    );
    serve(listener, app, limits, shutdown()).await?;
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
