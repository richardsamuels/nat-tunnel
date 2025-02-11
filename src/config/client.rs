use crate::Result;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChannelLimits {
    // The size of the channel that sends data from a tunnel to the
    // client/server
    #[serde(default = "super::common::default_core_channel")]
    pub core: usize,
}

impl Default for ChannelLimits {
    fn default() -> Self {
        Self {
            core: super::common::default_core_channel(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    #[serde(deserialize_with = "super::common::de_psk")]
    pub psk: String,
    pub addr: String,
    #[serde(default)]
    pub transport: super::common::Transport,
    #[serde(default = "default_mtu", deserialize_with = "warn_mtu")]
    pub mtu: u16,
    #[serde(deserialize_with = "de_tunnels")]
    pub tunnels: HashMap<u16, Tunnel>,
    pub crypto: Option<CryptoConfig>,
    #[serde(default)]
    pub channel_limits: ChannelLimits,
    #[serde(default)]
    pub timeouts: super::common::Timeout,
}

fn de_tunnels<'de, D>(deserializer: D) -> std::result::Result<HashMap<u16, Tunnel>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let tunnels: Vec<Tunnel> = Vec::<Tunnel>::deserialize(deserializer)?;
    let tunnel_map: HashMap<_, _> = tunnels.into_iter().map(|c| (c.remote_port, c)).collect();
    Ok(tunnel_map)
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CryptoConfig {
    #[serde(default = "localhost_ipv4", deserialize_with = "de_sni_name")]
    pub sni_name: String,

    // Note: we defer parsing the certificate file because keys/certs can't
    // /shouldn't be moved around in memory
    #[serde(default, deserialize_with = "de_ca_file")]
    pub ca: Option<PathBuf>,

    #[serde(default)]
    pub allow_self_signed: bool,
}

fn de_sni_name<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let sni_name: String = String::deserialize(deserializer)?;
    if rustls::pki_types::ServerName::try_from(sni_name.clone()).is_err() {
        return Err(serde::de::Error::custom(
            "sni_name invalid. expected IP address or hostname",
        ));
    }
    Ok(sni_name)
}

fn de_ca_file<'de, D>(deserializer: D) -> std::result::Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path: Option<PathBuf> = Option::<PathBuf>::deserialize(deserializer)?;
    if let Some(ref p) = path {
        if !p.exists() {
            return Err(serde::de::Error::custom(format!(
                "CA file does not exist: {:?}",
                p
            )));
        }
    }
    Ok(path)
}

fn localhost_ipv4() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Tunnel {
    pub remote_port: u16,
    #[serde(default = "localhost_ipv4")]
    pub local_hostname: String,
    pub local_port: u16,
    #[serde(default = "Option::default", skip_serializing)]
    pub crypto: Option<CryptoConfig>,
}

#[derive(Debug)]
pub struct Crypto {
    pub ca: Vec<CertificateDer<'static>>,
}

impl Crypto {
    pub fn from_config(cfg: &CryptoConfig) -> Result<Crypto> {
        Self::new(&cfg.ca)
    }

    fn new<P: AsRef<Path> + std::fmt::Debug>(ca_file: &Option<P>) -> Result<Crypto> {
        use rustls_pki_types::{pem::PemObject, CertificateDer};

        let ca: Vec<_> = match ca_file {
            None => Vec::new(),
            Some(ca_file) => CertificateDer::pem_file_iter(ca_file)
                .with_context(|_| crate::config::CertificateSnafu {})?
                .filter_map(|x| x.ok())
                .collect(),
        };
        Ok(Crypto { ca })
    }
}

pub fn load_config(config: &Path) -> crate::config::Result<Config> {
    let config_contents = read_to_string(config).with_context(|_| crate::config::IoSnafu {
        message: format!("failed to read config file '{:?}'", config),
    })?;

    let c: Config =
        toml::from_str(&config_contents).with_context(|_| crate::config::DecodeSnafu {})?;
    Ok(c)
}
