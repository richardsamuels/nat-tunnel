use simple_tunnel::{config, Result, client};
use tracing::{error, info};
use tokio::net as tnet;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let c = config::load_client_config();
    let addr = format!("{}:{}", c.addr, c.port);
    loop {
        info!("Handshaking with {}", &addr);
        let client_stream = tnet::TcpStream::connect(&addr).await?;
        let mut client = client::Client::new(client_stream)?;

        if let Err(e) = client.push_tunnel_config(&c).await {
            error!(cause = ?e, "failed to push tunnel config");
            break;
        };
        loop {
            if let Err(e) = client.run(&c).await {
                error!(cause = ?e, "failed to push tunnel config");
                break;
            }
        }
    }
    Ok(())
}
