use crate::config::Result as CResult;
use crate::Result;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::fs::read_to_string;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::vec::Vec;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChannelLimits {
    // The size of the channel that accepts incoming, unauthenticated, streams
    #[serde(default = "default_stream_channel")]
    pub stream_channels: usize,

    // The size of the channel that sends data from a tunnel to the
    // client/server
    #[serde(default = "super::common::default_core_channel")]
    pub core: usize,
}

impl Default for ChannelLimits {
    fn default() -> Self {
        Self {
            stream_channels: default_stream_channel(),
            core: super::common::default_core_channel(),
        }
    }
}

fn default_stream_channel() -> usize {
    16
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub psk: String,
    pub addr: SocketAddr,
    #[serde(default)]
    pub transport: super::common::Transport,
    #[serde(default = "default_mtu", deserialize_with = "warn_mtu")]
    pub mtu: u16,
    pub crypto: Option<CryptoConfig>,
    #[serde(default)]
    pub channel_limits: ChannelLimits,
    #[serde(default)]
    pub timeouts: super::common::Timeout,
}

fn default_mtu() -> u16 {
    1500
}

fn warn_mtu<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u16::deserialize(deserializer)?;
    eprintln!("Warning: mtu parameter is currently ignored.");
    Ok(value)
}

pub fn load_config(config: &Path) -> CResult<Config> {
    let config_contents = read_to_string(config).with_context(|_| crate::config::IoSnafu {
        message: format!("failed to read config file '{:?}'", config),
    })?;

    toml::from_str(&config_contents).with_context(|_| crate::config::DecodeSnafu {})
}

// Note: we defer parsing the file because keys/certs can't
// /shouldn't be moved around in memory
#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoConfig {
    #[serde(deserialize_with = "de_key_file")]
    pub key: PathBuf,
    #[serde(deserialize_with = "de_cert_file")]
    pub cert: PathBuf,
}

fn de_key_file<'de, D>(deserializer: D) -> std::result::Result<PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path: PathBuf = PathBuf::deserialize(deserializer)?;
    if !path.exists() {
        return Err(serde::de::Error::custom(format!(
            "key file does not exist: {:?}",
            path
        )));
    }
    Ok(path)
}

fn de_cert_file<'de, D>(deserializer: D) -> std::result::Result<PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path: PathBuf = PathBuf::deserialize(deserializer)?;
    if !path.exists() {
        return Err(serde::de::Error::custom(format!(
            "cert file does not exist: {:?}",
            path
        )));
    }
    Ok(path)
}

#[derive(Debug)]
pub struct Crypto {
    pub key: PrivateKeyDer<'static>,
    pub certs: Vec<CertificateDer<'static>>,
}

impl Crypto {
    pub fn from_crypto_cfg(cfg: &CryptoConfig) -> Result<Crypto> {
        Self::new(&cfg.key, &cfg.cert)
    }

    fn new<P: AsRef<Path>, Q: AsRef<Path> + std::fmt::Debug>(key: P, cert: Q) -> Result<Crypto> {
        use rustls_pki_types::{pem::PemObject, CertificateDer};

        let certs: Vec<_> = CertificateDer::pem_file_iter(&cert)
            .with_context(|_| crate::config::CertificateSnafu {})?
            .filter_map(|x| x.ok())
            .collect();

        let key = PrivateKeyDer::from_pem_file(&key)
            .with_context(|_| crate::config::InvalidKeySnafu {})?;

        Ok(Crypto { key, certs })
    }
}
