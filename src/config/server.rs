use crate::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use rustls_pemfile::{certs, rsa_private_keys};

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub psk: String,
    pub port: u16,
    pub crypto: Option<ServerCryptoConfig>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    #[arg(short, long, default_value = "./sts.toml")]
    pub config: PathBuf,
}

pub fn load_server_config(config: &Path) -> ServerConfig {
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
pub struct ServerCryptoConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
}

#[derive(Debug)]
pub struct ServerCrypto {
    pub key: PrivateKeyDer<'static>,
    pub certs: Vec<CertificateDer<'static>>,
}

impl ServerCrypto {
    pub fn from_crypto_cfg(cfg: &ServerCryptoConfig) -> Result<ServerCrypto> {
        Self::new(&cfg.key, &cfg.cert)
    }

    fn new<P: AsRef<Path>, Q: AsRef<Path>>(key: P, cert: Q) -> Result<ServerCrypto> {
        use std::fs::File;
        use std::io::BufReader;

        let key: PrivatePkcs1KeyDer = rsa_private_keys(&mut BufReader::new(File::open(&key)?))
            .next()
            .unwrap()
            .map(Into::into)?;

        let certs_: Vec<_> = certs(&mut BufReader::new(File::open(&cert)?))
            .filter_map(|x| x.ok())
            .collect();
        Ok(ServerCrypto {
            key: key.into(),
            certs: certs_,
        })
    }
}
