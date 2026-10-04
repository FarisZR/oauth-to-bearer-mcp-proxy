use std::{fs::OpenOptions, io::Write, path::Path};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, de::DeserializeOwned};

pub struct Sealer {
    cipher: XChaCha20Poly1305,
    binding: String,
}

impl Sealer {
    /// The same key survives restarts. Configuration binds every sealed object
    /// to this public endpoint and upstream, even if a key file is accidentally reused.
    pub fn load(path: &Path, binding: String) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).context("cannot create token-key directory")?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(mut file) => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                file.write_all(&key).context("cannot write token key")?;
                file.sync_all().context("cannot persist token key")?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err).context("cannot create token key"),
        }
        let key = std::fs::read(path).context("cannot read token key")?;
        ensure!(
            key.len() == 32,
            "token key must contain exactly 32 bytes; do not replace an existing key unless you intend to disconnect clients"
        );
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(&key).unwrap(),
            binding,
        })
    }

    fn context(&self, purpose: &str) -> String {
        format!("oauth-to-bearer-mcp-proxy:v1:{purpose}:{}", self.binding)
    }

    pub fn seal<T: Serialize>(&self, purpose: &str, value: &T) -> Result<String> {
        let plaintext = serde_json::to_vec(value)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: self.context(purpose).as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("cannot encrypt token"))?;
        let mut bytes = nonce.to_vec();
        bytes.extend(encrypted);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn open<T: DeserializeOwned>(&self, purpose: &str, token: &str) -> Option<T> {
        if token.len() > 64 * 1024 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
        if bytes.len() < 40 {
            return None;
        }
        let plaintext = self
            .cipher
            .decrypt(
                XNonce::from_slice(&bytes[..24]),
                Payload {
                    msg: &bytes[24..],
                    aad: self.context(purpose).as_bytes(),
                },
            )
            .ok()?;
        serde_json::from_slice(&plaintext).ok()
    }
}

pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
