use crate::net as stnet;
use crate::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, rsa_private_keys};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub psk: String,
    pub port: u16,
    #[serde(default = "default_mtu", deserialize_with = "warn_mtu")]
    pub mtu: u16,
    pub crypto: Option<CryptoConfig>,
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = "./sts.toml")]
    pub config: PathBuf,
}

pub fn load_config(config: &Path) -> Config {
    let config_contents = match read_to_string(config) {
        Ok(args) => args,
        Err(e) => panic!("Failed to read config file '{:?}'. Error: {}", &config, e),
    };

    match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => panic!("Failed to parse config file '{:?}'.\n{}", config, e),
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
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
        use std::fs::File;
        use std::io::BufReader;

        let cert_fh = File::open(&cert).context(stnet::IoSnafu {
            message: "failed to load key file",
        })?;

        let certs_: Vec<_> = certs(&mut BufReader::new(cert_fh))
            .filter_map(|x| x.ok())
            .collect();

        let key_fh = File::open(&key).context(stnet::IoSnafu {
            message: "failed to load key file",
        })?;
        let key = rsa_private_keys(&mut BufReader::new(key_fh))
            .next()
            .expect("invalid private key. (Convert your key with: openssl rsa -in your.key -out new.key -traditional)")
            .map(Into::into)?;

        Ok(Crypto { key, certs: certs_ })
    }
}
