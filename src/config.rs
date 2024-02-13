use crate::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::vec::Vec;
use std::collections::HashSet;

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
    pub crypto: Option<Crypto>,
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
pub struct Crypto {
    pub key: PathBuf,
    pub cert: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub psk: String,
    pub port: u16,
    pub crypto: Option<Crypto>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    #[arg(short, long, default_value = "./sts.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClientArgs {
    #[arg(short, long, default_value = "./stc.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
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

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    GenerateKey {},
}

pub async fn generate_key(_config_file: &Path, _target: &str) -> Result<()> {
    unimplemented!();
}
