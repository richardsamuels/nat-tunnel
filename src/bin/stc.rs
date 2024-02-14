use clap::Parser;
use simple_tunnel::{client, config::client as config, net as stnet};
use std::process::exit;
use std::sync::Arc;
use tokio::net as tnet;
use tokio_rustls::TlsConnector;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = config::ClientArgs::parse();

    let c = config::load_client_config(&args.config);
    let crypto_cfg = c
        .crypto
        .as_ref()
        .map(|c| crypto_init(c).expect("failed to load cert files"));

    let mut tries = 5;
    loop {
        let addr = format!("{}:{}", &c.addr, &c.port);
        tries -= 1;
        if tries == 0 {
            error!("connection failed after {} retries. giving up", tries);
            exit(1);
        }

        info!("Handshaking with {}", &addr);
        let client_stream = match tnet::TcpStream::connect(&addr).await {
            Err(e) => {
                error!(cause = ?e, addr = addr, "failed to connect to Server");
                exit(1);
            }
            Ok(s) => s,
        };
        let result = if let Some(ref crypto_cfg) = crypto_cfg {
            // TODO SNI
            let domain = rustls::pki_types::ServerName::try_from("127.0.0.1")
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname")
                })
                .expect("domain name did not parse")
                .to_owned();
            let conn = TlsConnector::from(crypto_cfg.clone());
            let client_stream = conn
                .connect(domain, client_stream)
                .await
                .expect("TLS failure");
            let mut client = client::Client::new(&c, client_stream);
            tries = 5;
            client.run().await
        } else {
            let mut client = client::Client::new(&c, client_stream);
            tries = 5;
            client.run().await
        };

        match result {
            Err(stnet::Error::ConnectionDead) => {
                error!("client has failed. Reconnecting");
                continue;
            }
            e => {
                error!(cause = ?e, "client has failed. Not restarting");
                exit(1);
            }
        }
    }
}

fn crypto_init(
    c: &config::ClientCryptoConfig,
) -> simple_tunnel::net::Result<Arc<rustls::ClientConfig>> {
    let crypto_cfg = config::ClientCrypto::from_config(c)?;
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
