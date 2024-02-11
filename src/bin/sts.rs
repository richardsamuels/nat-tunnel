use clap::Parser;
use simple_tunnel::{config, server, Result};
use std::net::SocketAddr;
use std::process::ExitCode;
use tokio::net as tnet;
use tracing::{error, info};

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    let args = config::ServerArgs::parse();

    let c = config::load_server_config(&args.config);

    if let Some(config::Commands::GenerateKeyPair { bits }) = args.command {
        config::generate_key_pair(&args.config, "sts", bits);
    }

    match tokio(c) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!(cause =?e, "exiting");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn tokio(c: config::ServerConfig) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", &c.port).parse().unwrap();
    info!("listening on {}", &addr);
    let listener = tnet::TcpListener::bind(addr).await?;

    let mut transport = server::Server::new(c, listener);
    match transport.run().await {
        Err(e) => return Err(e),
        Ok(()) => Ok(()),
    }
}
