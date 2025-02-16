use clap::Parser;
use color_eyre::eyre::{Report, Result as CEResult};
use nat_tunnel::{config::server as config, net::IoSnafu, server};
use snafu::ResultExt;
use std::process::exit;
use tokio::net as tnet;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./sts.toml")]
    pub config: std::path::PathBuf,
    #[arg(long, default_value = "false")]
    pub allow_insecure_transport: bool,
}

#[tokio::main]
async fn main() -> CEResult<()> {
    tracing_subscriber::fmt::init();
    color_eyre::install()?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .install_default()
        .expect("failed to install crypto provider");
    let args = Args::parse();

    let c = config::load_config(&args.config)?;
    if c.crypto.is_none() && !args.allow_insecure_transport {
        panic!("Insecure transport in use without --allow-insecure-transport");
    }
    if c.crypto.is_none() && matches!(c.transport, nat_tunnel::config::Transport::Quic) {
        panic!("QUIC is enabled, but TLS cert/key file were not provided. Try setting `transport = \"tcp\"` or providing cert/key file");
    }

    let token = CancellationToken::new();

    let shutdown_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for event");
        info!("Received SIGINT. Terminating all connections and shutting down...");
        shutdown_token.cancel();
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for event");
        info!("Received SIGINT twice, ungraceful shutdown initiated");
        exit(1);
    });

    // TODO wow lazy
    use nat_tunnel::config::Transport;
    match c.transport {
        Transport::Tcp => {
            let listener = tnet::TcpListener::bind(c.addr)
                .await
                .with_context(|_| IoSnafu {
                    message: format!("failed to bind {}", c.addr),
                })?;
            let mut transport = server::TcpServer::new(c, token.clone(), listener).unwrap();

            transport.run().await.map_err(Report::from)
        }
        Transport::Quic => {
            let mut transport = server::QuicServer::new(c, token.clone()).unwrap();
            transport.run().await.map_err(Report::from)
        }
    }
}
