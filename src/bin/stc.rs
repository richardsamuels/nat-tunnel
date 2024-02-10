use simple_tunnel::{config, Result, client, net as stnet};
use tracing::{error, info};
use tokio::net as tnet;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let mut tries = 5;
    loop {
        let c = config::load_client_config();
        let addr = format!("{}:{}", c.addr, c.port);
        tries -= 1;
        if tries == 0 {
            error!("connection failed after retries. giving up");
            return Err("".into());
        }

        info!("Handshaking with {}", &addr);
        let client_stream = tnet::TcpStream::connect(&addr).await?;
        let mut client = client::Client::new(c, client_stream)?;

        if let Err(e) = client.push_tunnel_config().await {
            error!(cause = ?e, "failed to push tunnel config");
            return Err(e);
        };
        tries = 5;

        if let Err(e) = client.run().await {
            match e {
                stnet::Error::ConnectionDead => {
                    error!(cause = ?e, "client has failed. Reconnecting");
                    continue;
                }
                e => {
                    error!(cause = ?e, "client has failed. Not restarting");
                    return Err(e.into());
                }
            }
        }
    }
}
