use crate::net as stnet;
use crate::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::collections::HashSet;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;

use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;

#[derive(Debug, Deserialize, Serialize)]
pub struct Tunnel {
    pub remote_port: u16,
    #[serde(default = "localhost_ipv4")]
    pub local_hostname: String,
    pub local_port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub psk: String,
    pub addr: String,
    pub port: u16,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub tunnels: Vec<Tunnel>,
    pub crypto: Option<CryptoConfig>,
}

fn default_mtu() -> u16 {
    1500
}

impl Config {
    /// Lookup `local_port` for a given `remote_port`
    pub fn tunnel(&self, remote_port: u16) -> Option<&Tunnel> {
        self.tunnels.iter().find(|t| t.remote_port == remote_port)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoConfig {
    #[serde(default = "localhost_ipv4")]
    pub sni_name: String,
    pub ca: Option<PathBuf>,
}

fn localhost_ipv4() -> String {
    "127.0.0.1".to_string()
}

#[derive(Debug)]
pub struct Crypto {
    pub ca: Vec<CertificateDer<'static>>,
}

impl Crypto {
    pub fn from_config(cfg: &CryptoConfig) -> Result<Crypto> {
        Self::new(&cfg.ca)
    }

    fn new<P: AsRef<Path> + std::fmt::Debug>(ca: &Option<P>) -> Result<Crypto> {
        use std::fs::File;
        use std::io::BufReader;

        let ca_: Vec<_> = match ca {
            None => Vec::new(),
            Some(ca) => {
                let ca_fh = File::open(ca).context(stnet::IoSnafu {
                    message: "failed to read ca file",
                })?;

                certs(&mut BufReader::new(ca_fh))
                    .filter_map(|x| x.ok())
                    .collect()
            }
        };
        Ok(Crypto { ca: ca_ })
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = "./stc.toml")]
    pub config: PathBuf,
}

pub fn load_config(config: &Path) -> Config {
    let config_contents = match read_to_string(config) {
        Ok(args) => args,
        Err(e) => panic!("Failed to read config file '{:?}'. Error: {}", &config, e),
    };

    let c: Config = match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => panic!("Failed to parse config file '{:?}'.\n{}", config, e),
    };

    if c.psk.len() > 512 || c.psk.is_empty() {
        panic!("psk length must be (0, 512] bytes");
    }
    if c.addr.is_empty() {
        panic!("addr must not be empty");
    }

    if c.crypto.is_some() {
        rustls::pki_types::ServerName::try_from(c.crypto.as_ref().unwrap().sni_name.clone())
            .expect("sni_name must be a valid DNS name or IP address");
    }

    let mut temp = HashSet::new();
    for t in &c.tunnels {
        if temp.contains(&t.remote_port) {
            panic!(
                "Configuration file contains duplicate remote_ports: {}",
                t.remote_port
            );
        }
        temp.insert(t.remote_port);
    }

    c
}
