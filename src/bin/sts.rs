use simple_tunnel::Result;
use simple_tunnel::{config};
use simple_tunnel::remote;
use std::net::SocketAddr;
use tracing::{error, info};
use tokio::net as tnet;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let c = config::load_server_config();

    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let mut transport = remote::Remote::new(c, listener);
    match transport.run().await {
        Err(e) => return Err(e),
        Ok(()) => Ok(()),
    }
}
