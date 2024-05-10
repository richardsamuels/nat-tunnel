use clap::Parser;
use simple_tunnel::Result;
use simple_tunnel::{client, config::client as config};
use std::process::exit;
use std::sync::Arc;
use tokio::net as tnet;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    color_eyre::install().unwrap();
    let args = config::Args::parse();

    let c = config::load_config(&args.config);
    let crypto_cfg = c
        .crypto
        .as_ref()
        .map(|c| crypto_init(c).expect("failed to load cert files"));

    let token = CancellationToken::new();
    tokio::select! {
        maybe_run = run(c, token.clone(), &crypto_cfg ) => {
            match maybe_run {
                Ok(_) => exit(0),
                e => {
                    error!(cause = ?e, "client has failed.");
                    exit(1);
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
    let addr = format!("{}:{}", &c.addr, &c.port);
    info!("Handshaking with {}", &addr);
    let client_stream = match tnet::TcpStream::connect(&addr).await {
        Err(e) => {
            error!(cause = ?e, addr = addr, "failed to connect to Server");
            return Err(e.into());
        }
        Ok(s) => s,
    };
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
        let mut client = client::Client::new(c, token, client_stream);
        client.run().await
    } else {
        let mut client = client::Client::new(c, token, client_stream);
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
