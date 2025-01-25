use clap::Parser;
use color_eyre::eyre::Result;
use simple_tunnel::{config::server as config, server};
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    color_eyre::install()?;
    let args = config::Args::parse();

    let c = config::load_config(&args.config);

    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let token = CancellationToken::new();
    let mut transport = server::Server::new(c, token.clone(), listener).unwrap();

    tokio::select! {
        ret = transport.run() => return ret,
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT. Terminating all connections and shutting down...");
            transport.shutdown().await?;
        }
    };
    Ok(())
}
