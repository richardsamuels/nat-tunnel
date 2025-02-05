use clap::Parser;
use simple_tunnel::net::Error;
use simple_tunnel::Result;
use simple_tunnel::{client, config::client as config};
use std::process::exit;
use std::sync::Arc;
use tokio::net as tnet;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./stc.toml")]
    pub config: std::path::PathBuf,
    #[arg(long, default_value = "false")]
    pub allow_insecure_transport: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    color_eyre::install().unwrap();
    let args = Args::parse();

    let c = config::load_config(&args.config).expect("invalid config");
    if c.crypto.is_none() && !args.allow_insecure_transport {
        panic!("Insecure transport in use without --allow-insecure-transport");
    }
    let crypto_cfg = c
        .crypto
        .as_ref()
        .map(|c| crypto_init(c).expect("failed to load cert files"));

    let token = CancellationToken::new();
    let mut failures = 0;
    let mut last_failure = std::time::Instant::now();

    // Spawn a separate task to handle SIGINT
    let shutdown_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for event");
        info!("Received SIGINT, shutting down...");
        shutdown_token.cancel();
    });

    loop {
        tokio::select! {
            maybe_run = run(c.clone(), token.clone(), &crypto_cfg) => {
                match maybe_run {
                    Ok(_) => exit(0),
                    Err(e) if matches!(e.downcast_ref(), Some(Error::ConnectionDead)) => {
                        if last_failure.elapsed() >= std::time::Duration::from_secs(5) {
                            failures = 0;
                        }
                        last_failure = std::time::Instant::now();
                        failures += 1;
                        if failures >= 5 {
                            error!("client has failed 5 times in 5 seconds. Exiting");
                            exit(1);
                        }
                        error!(cause = ?e, "client has failed. attempting recovery");
                    }
                    Err(e) => {
                        error!(cause = ?e, "client has failed with unrecoverable error");
                        exit(1);
                    }
                }
            }
        }
    }
}

async fn run(
    c: config::Config,
    token: CancellationToken,
    crypto_cfg: &Option<Arc<rustls::ClientConfig>>,
) -> Result<()> {
    info!("Handshaking with {}", &c.addr);
    let client_stream = match tnet::TcpStream::connect(&c.addr).await {
        Err(e) => {
            error!(cause = ?e, addr = ?c.addr, "failed to connect to Server");
            return Err(e.into());
        }
        Ok(s) => s,
    };
    let client_stream = client_stream
        .into_std()
        .expect("failed to get std TcpStream");
    simple_tunnel::net::set_keepalive(&client_stream)
        .expect("keepalive should be enabled on stream, but operation failed");
    let client_stream = tnet::TcpStream::from_std(client_stream)?;

    let peer_addr = client_stream.peer_addr().expect("ip");

    client_stream
        .set_nodelay(true)
        .expect("Could not set TCP_NODELAY on socket");

    if let Some(ref crypto_cfg) = crypto_cfg {
        let domain =
            rustls::pki_types::ServerName::try_from(c.crypto.as_ref().unwrap().sni_name.clone())
                .unwrap()
                .to_owned();

        let conn = TlsConnector::from(crypto_cfg.clone());
        let client_stream = conn
            .connect(domain, client_stream)
            .await
            .expect("TLS initialization failed");

        info!("TLS enabled. All connections to the Server will be encrypted.");
        let mut client = client::Client::new(c, token.clone(), peer_addr, client_stream);
        client.run().await
    } else {
        let mut client = client::Client::new(c, token.clone(), peer_addr, client_stream);
        client.run().await
    }
}

fn crypto_init(c: &config::CryptoConfig) -> Result<Arc<rustls::ClientConfig>> {
    let crypto_cfg = config::Crypto::from_config(c)?;
    let mut root_cert_store = rustls::RootCertStore::empty();
    if !crypto_cfg.ca.is_empty() {
        for cert in crypto_cfg.ca {
            root_cert_store.add(cert).unwrap();
        }
    } else {
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
