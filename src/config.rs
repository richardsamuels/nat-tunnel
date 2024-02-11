use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
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
    pub crypto: Option<Crypto>,
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
pub struct Crypto {
    key: PathBuf,
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

    if c.psk.len() > 512 {
        panic!("psk must not be longer than 512 bytes");
    }

    c
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    GenerateKeyPair {
        #[arg(short, long, default_value = "4096")]
        bits: u16,
    },
}

pub fn generate_key_pair(config_file: &Path, target: &str, bits: u16) {
    println!("Attempting to generate a keypair with openssl");
    let parent = config_file.parent().unwrap().canonicalize().unwrap();
    if !parent.is_dir() {
        eprintln!(
            "Path {:?} does not appear to be a directory. Giving up on key generation",
            parent
        );
        exit(1);
    }

    let private_key: PathBuf = [parent, format!("{}.key", target).into()].iter().collect();

    println!("Creating key at {:?}", private_key);
    Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(&private_key)
        .arg(bits.to_string())
        .output()
        .expect("Failed to generate private key");

    println!("Add the following to {:?}:\n", private_key);
    println!("[crypto]");
    println!("key = \"{}\"", private_key.to_str().unwrap());

    exit(0);
}
