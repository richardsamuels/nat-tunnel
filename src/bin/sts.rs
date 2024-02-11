use simple_tunnel::{config, server, Result};
use std::net::SocketAddr;
use tracing::{error, info};
use tokio::net as tnet;

//#[tokio::main]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let c = config::load_server_config();

    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let mut transport = server::Server::new(c, listener);
    match transport.run().await {
        Err(e) => return Err(e),
        Ok(()) => Ok(()),
    }
}
