use clap::Parser;
use simple_tunnel::{config, server, Result};
use std::net::SocketAddr;
use std::process::exit;
use tokio::net as tnet;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = config::ServerArgs::parse();

    let c = config::load_server_config(&args.config);

    if let Some(config::Commands::GenerateKey {}) = args.command {
        config::generate_key(&args.config, "sts").await?;
        exit(0);
    }

    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let mut transport = server::Server::new(c, listener);
    match transport.run().await {
        Err(e) => return Err(e),
        Ok(()) => Ok(()),
    }
}
