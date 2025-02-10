use clap::Parser;
use color_eyre::eyre::Result;
use simple_tunnel::{config::server as config, server};
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
async fn main() -> Result<()> {
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
    if c.crypto.is_none() && matches!(c.transport, simple_tunnel::config::Transport::Quic) {
        panic!("QUIC is enabled, but TLS cert/key file were not provided. Try setting `transport = \"tcp\"` or providing cert/key file");
    }

    let token = CancellationToken::new();

    // TODO wow lazy
    use simple_tunnel::config::Transport;
    match c.transport {
        Transport::Tcp => {
            let listener = tnet::TcpListener::bind(c.addr).await?;
            let mut transport = server::TcpServer::new(c, token.clone(), listener).unwrap();

            tokio::select! {
                ret = transport.run() => return ret,
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT. Terminating all connections and shutting down...");
                    let _ = transport.shutdown().await;
                }
            };
        }
        Transport::Quic => {
            let mut transport = server::QuicServer::new(c, token.clone()).unwrap();
            tokio::select! {
                ret = transport.run() => return ret,
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT. Terminating all connections and shutting down...");
                    let _ = transport.shutdown().await;
                }
            };
        }
    };

    Ok(())
}
