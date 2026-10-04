use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public origin; the client-facing MCP endpoint is always /mcp.
    pub public_url: Url,
    /// Exact upstream Streamable HTTP endpoint, including any query string.
    pub upstream_url: Url,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_key_file")]
    pub token_key_file: PathBuf,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_timeout")]
    pub upstream_header_timeout_seconds: u64,
    #[serde(default)]
    pub oauth: OAuthConfig,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    /// Optional pre-registered client: its secret is the upstream API key.
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}

fn default_key_file() -> PathBuf {
    "data/token.key".into()
}

fn default_name() -> String {
    "MCP server".into()
}

fn default_timeout() -> u64 {
    300
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let config: Self = toml::from_str(&text).context("invalid TOML configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        validate_http_url(&self.public_url)?;
        ensure!(
            self.public_url.path() == "/"
                && self.public_url.query().is_none()
                && self.public_url.fragment().is_none(),
            "public_url must be an origin without a path, query, or fragment"
        );
        ensure!(
            self.public_url.scheme() == "https" || is_loopback(&self.public_url),
            "public_url must use HTTPS (HTTP is allowed only on loopback for local development)"
        );
        validate_http_url(&self.upstream_url)?;
        ensure!(
            self.upstream_url.fragment().is_none(),
            "upstream_url cannot have a fragment"
        );
        ensure!(
            !self.token_key_file.as_os_str().is_empty(),
            "token_key_file cannot be empty"
        );
        ensure!(
            !self.name.is_empty() && self.name.len() <= 200,
            "name must have 1 to 200 bytes"
        );
        ensure!(
            self.upstream_header_timeout_seconds > 0,
            "upstream timeout must be positive"
        );
        ensure!(
            self.allowed_origins.len() <= 32,
            "at most 32 allowed_origins are supported"
        );
        for origin in &self.allowed_origins {
            let url = Url::parse(origin).context("invalid allowed_origin")?;
            validate_http_url(&url)?;
            ensure!(
                url.origin().ascii_serialization() == *origin,
                "allowed_origins must contain exact origins, without trailing slashes"
            );
        }
        match &self.oauth.client_id {
            Some(id) => {
                ensure!(
                    !id.is_empty() && id.len() <= 200 && !id.starts_with("dcr_"),
                    "oauth.client_id must have 1 to 200 bytes and cannot start with dcr_"
                );
                ensure!(
                    !self.oauth.redirect_uris.is_empty(),
                    "oauth.redirect_uris is required for a pre-registered client"
                );
            }
            None => ensure!(
                self.oauth.redirect_uris.is_empty(),
                "oauth.redirect_uris requires oauth.client_id"
            ),
        }
        validate_redirects(&self.oauth.redirect_uris)?;
        Ok(())
    }

    pub fn issuer(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }

    pub fn resource(&self) -> String {
        format!("{}/mcp", self.issuer())
    }

    pub fn origins(&self) -> Vec<String> {
        let mut origins = self.allowed_origins.clone();
        origins.push(self.issuer());
        origins
    }
}

fn validate_http_url(url: &Url) -> Result<()> {
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "URLs must use HTTP or HTTPS"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URLs cannot contain credentials"
    );
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

pub fn validate_redirects(uris: &[String]) -> Result<()> {
    ensure!(uris.len() <= 5, "at most five redirect URIs are supported");
    for uri in uris {
        ensure!(uri.len() <= 512, "redirect URI cannot exceed 512 bytes");
        let url = Url::parse(uri).context("redirect URI must be an absolute URL")?;
        validate_http_url(&url)?;
        if url.scheme() != "https" && !is_loopback(&url) {
            bail!("redirect URI must use HTTPS or a loopback HTTP address");
        }
        ensure!(
            url.fragment().is_none(),
            "redirect URI cannot have a fragment"
        );
        ensure!(
            !url.query_pairs().any(|(key, _)| matches!(
                key.as_ref(),
                "code" | "state" | "iss" | "error" | "error_description"
            )),
            "redirect URI cannot contain OAuth response parameters"
        );
    }
    Ok(())
}
