use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::vec::Vec;

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
}

impl ClientConfig {
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
pub struct ServerConfig {
    pub psk: String,
    pub port: u16,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    #[arg(short, long, default_value = "./sts.toml")]
    pub config: String,
}

pub fn load_server_config() -> ServerConfig {
    let args = ServerArgs::parse();
    let config_contents = match read_to_string(&args.config) {
        Ok(args) => args,
        Err(e) => panic!(
            "Failed to read config file '{}'. Error: {}",
            &args.config, e
        ),
    };

    match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => panic!("Failed to parse config file '{}'.\n{}", args.config, e),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClientArgs {
    #[arg(short, long, default_value = "./stc.toml")]
    config: String,
}

pub fn load_client_config() -> ClientConfig {
    let args = ClientArgs::parse();
    let config_contents = match read_to_string(&args.config) {
        Ok(args) => args,
        Err(e) => panic!(
            "Failed to read config file '{}'. Error: {}",
            &args.config, e
        ),
    };

    let c: ClientConfig = match toml::from_str(&config_contents) {
        Ok(c) => c,
        Err(e) => panic!("Failed to parse config file '{}'.\n{}", args.config, e),
    };

    if c.psk.len() > 512 {
        panic!("psk must not be longer than 512 bytes");
    }

    c
}
