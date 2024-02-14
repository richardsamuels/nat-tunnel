use crate::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use rustls_pemfile::{certs, rsa_private_keys};

#[derive(Debug, Deserialize, Serialize)]
pub struct Tunnel {
    pub remote_port: u16,
    pub local_port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientConfig {
    pub psk: String,
    pub addr: String,
    pub port: u16,
    pub tunnels: Vec<Tunnel>,
    pub crypto: Option<ClientCryptoConfig>,
}

impl ClientConfig {
    /// Lookup `local_port` for a given `remote_port`
    pub fn local_port(&self, remote_port: u16) -> Option<u16> {
        for t in &self.tunnels {
            if t.remote_port == remote_port {
                return Some(t.local_port);
            }
        }
        None
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientCryptoConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
    pub ca: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ClientCrypto {
    pub key: PrivateKeyDer<'static>,
    pub certs: Vec<CertificateDer<'static>>,
    pub ca: Vec<CertificateDer<'static>>,
}

impl ClientCrypto {
    pub fn from_config(cfg: &ClientCryptoConfig) -> Result<ClientCrypto> {
        Self::new(&cfg.key, &cfg.cert, &cfg.ca)
    }

    fn new<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
        key: P,
        cert: Q,
        ca: &Option<R>,
    ) -> Result<ClientCrypto> {
        use std::fs::File;
        use std::io::BufReader;

        let key: PrivatePkcs1KeyDer = rsa_private_keys(&mut BufReader::new(File::open(&key)?))
            .next()
            .unwrap()
            .map(Into::into)?;

        let certs_: Vec<_> = certs(&mut BufReader::new(File::open(&cert)?))
            .filter_map(|x| x.ok())
            .collect();
        let ca_: Vec<_> = match ca {
            None => Vec::new(),
            Some(ca) => certs(&mut BufReader::new(File::open(ca)?))
                .filter_map(|x| x.ok())
                .collect(),
        };
        Ok(ClientCrypto {
            key: key.into(),
            certs: certs_,
            ca: ca_,
        })
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClientArgs {
    #[arg(short, long, default_value = "./stc.toml")]
    pub config: PathBuf,
}

pub fn load_client_config(config: &Path) -> ClientConfig {
    let config_contents = match read_to_string(config) {
        Ok(args) => args,
        Err(e) => panic!("Failed to read config file '{:?}'. Error: {}", &config, e),
    };

    let c: ClientConfig = match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => panic!("Failed to parse config file '{:?}'.\n{}", config, e),
    };

    if c.psk.len() > 512 || c.psk.is_empty() {
        panic!("psk length must be [0, 512] bytes");
    }
    if c.addr.is_empty() {
        panic!("addr must not be empty");
    }

    let mut temp = HashSet::new();
    for t in &c.tunnels {
        if temp.contains(&t.remote_port) {
            panic!("Configuration file contains duplicate remote_ports.");
        }
        temp.insert(t.remote_port);
    }

    c
}
