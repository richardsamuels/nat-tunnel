use super::common::*;
use crate::{config::server as config,  Result};
use std::sync::{Arc, Mutex};
use tokio::net as tnet;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

pub struct TcpServer {
    config: Arc<config::Config>,
    token: CancellationToken,
    listener: tnet::TcpListener,
    active_tunnels: Arc<Mutex<ActiveTunnels>>,

    tls: Option<TlsAcceptor>,
    handlers: JoinSet<()>,
}

impl TcpServer {
    pub fn new(
        config: config::Config,
        token: CancellationToken,
        listener: tnet::TcpListener,
    ) -> Result<Self> {
        let acceptor = match config.crypto {
            None => None,
            Some(ref crypto_paths) => {
                let crypto = config::Crypto::from_crypto_cfg(crypto_paths)?;

                let tls_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(crypto.certs, crypto.key)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
                Some(TlsAcceptor::from(Arc::new(tls_config)))
            }
        };

        Ok(TcpServer {
            config: config.into(),
            token,
            listener,
            active_tunnels: Arc::new(ActiveTunnels::new().into()),
            tls: acceptor,
            handlers: JoinSet::new(),
        })
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        self.token.cancel();
        while self.handlers.join_next().await.is_some() {
            // intentionally blank
        }
        Ok(())
    }

    #[tracing::instrument(name = "TcpSupervisor", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        info!("listening on {}", &self.config.addr);
        if self.tls.is_some() {
            info!("TLS enabled. All connections to Clients will be encrypted.");
        } else {
            warn!("TLS *DISABLED*. All data is transmitted in the clear.");
        }
        let ret = loop {
            let (socket, addr) = tokio::select! {
                maybe_accept = self.listener.accept() => {
                    match maybe_accept {
                        Err(e) => {
                            error!(cause = ?e, "Failed to accept new client");
                            continue;
                        }
                        Ok(s) => s,
                    }
                }

                _ = self.token.cancelled() => {
                    break Ok(())
                }
            };
            if let Err(e) = socket.set_nodelay(true) {
                error!(e=?e, "Failed to set TCP_NODELAY on socket");
                continue;
            };

            if let Some(tls) = &self.tls {
                let peer_addr = socket.peer_addr().expect("ip");
                let socket = match tls.accept(socket).await {
                    Err(e) => {
                        error!(cause = ?e, addr = ?addr, "client connection dropped (failed to negotiate TLS)");
                        continue;
                    }
                    Ok(socket) => Box::new(socket),
                };
                let mut h = super::ClientHandler::new(
                    self.config.clone(),
                    self.token.clone(),
                    self.active_tunnels.clone(),
                    (peer_addr.into(), socket),
                );
                self.handlers.spawn(async move {
                    trace!(addr = ?addr, "client handler start");
                    if let Err(e) = h.run().await {
                        error!(cause = ?e, addr = ?addr, "client connection dropped");
                    }
                    trace!(addr = ?addr, "client handler end");
                });
            } else {
                let peer_addr = socket.peer_addr().expect("ip");
                let mut h = super::ClientHandler::new(
                    self.config.clone(),
                    self.token.clone(),
                    self.active_tunnels.clone(),
                    (peer_addr.into(), Box::new(socket)),
                );
                self.handlers.spawn(async move {
                    trace!(addr = ?addr, "client handler start");
                    if let Err(e) = h.run().await {
                        error!(cause = ?e, addr = ?addr, "client connection dropped");
                    }
                    trace!(addr = ?addr, "client handler end");
                });
            }
        };
        self.shutdown().await?;
        ret
    }
}
