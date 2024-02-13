use clap::Parser;
use simple_tunnel::{client, config, net as stnet};
use tokio::net as tnet;
use tracing::{error, info};

#[tokio::main]
async fn tokio(c: config::ClientConfig) {
    let mut tries = 5;
    loop {
        let addr = format!("{}:{}", &c.addr, &c.port);
        tries -= 1;
        if tries == 0 {
            error!("connection failed after {} retries. giving up", tries);
            return;
        }

        info!("Handshaking with {}", &addr);
        let client_stream = match tnet::TcpStream::connect(&addr).await {
            Err(e) => {
                error!(cause = ?e, addr = addr, "failed to connect to Server");
                return;
            }
            Ok(s) => s,
        };
        let mut client = client::Client::new(&c, client_stream);

        // TODO this logic retries if the auth info is bad
        tries = 5;

        if let Err(e) = client.run().await {
            match e {
                stnet::Error::ConnectionDead => {
                    error!(cause = ?e, "client has failed. Reconnecting");
                    continue;
                }
                e => {
                    error!(cause = ?e, "client has failed. Not restarting");
                    return;
                }
            }
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = config::ClientArgs::parse();

    let c = config::load_client_config(&args.config);

    if let Some(config::Commands::GenerateKey {}) = args.command {
        unimplemented!();
    }
    tokio(c);
}
