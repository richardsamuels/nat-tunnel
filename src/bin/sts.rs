use clap::Parser;
use simple_tunnel::{config::server as config, server, Result};
use std::net::SocketAddr;
use tokio::net as tnet;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = config::Args::parse();

    let c = config::load_config(&args.config);

    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let mut transport = server::Server::new(c, listener).unwrap();
    transport.run().await
}
