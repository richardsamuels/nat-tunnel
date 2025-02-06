use super::common::*;
use crate::{config::server as config, net as stnet, Result};
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

pub struct QuicServer {
    config: Arc<config::Config>,
    token: CancellationToken,
    active_tunnels: Arc<Mutex<ActiveTunnels>>,
    server: quinn::Endpoint,
    handlers: JoinSet<()>,
}

impl QuicServer {
    pub fn new(config: config::Config, token: CancellationToken) -> Result<Self> {
        let tls_config = match config.crypto {
            None => panic!("programmer error: missing cfg"),
            Some(ref crypto_paths) => {
                let crypto = config::Crypto::from_crypto_cfg(crypto_paths)?;

                quinn::ServerConfig::with_single_cert(crypto.certs, crypto.key)?
            }
        };
        let endpoint = quinn::Endpoint::server(tls_config, config.addr)?;

        Ok(QuicServer {
            server: endpoint,
            config: config.into(),
            token,
            active_tunnels: Arc::new(ActiveTunnels::new().into()),
            handlers: JoinSet::new(),
        })
    }
    async fn shutdown(&mut self) -> Result<()> {
        self.token.cancel();
        while self.handlers.join_next().await.is_some() {
            // intentionally blank
        }
        Ok(())
    }

    #[tracing::instrument(name = "QuicListener", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        info!("TLS enabled. All connections to Clients will be encrypted.");
        loop {
            let incoming = tokio::select! {
                maybe_accept = self.server.accept() => {
                    match maybe_accept {
                        None => {
                            info!("Failed to accept new client");
                            break
                        }
                        Some(s) => s,
                    }
                }

                _ = self.token.cancelled() => {
                    return Ok(())
                }
            };
            let id = incoming.orig_dst_cid();
            let conn = incoming.await?;

            let mut h = QuicStream::new(
                self.config.clone(),
                self.token.clone(),
                self.active_tunnels.clone(),
                id,
                conn,
            );
            self.handlers.spawn(async move {
                trace!(addr = ?id, "client handler start");
                if let Err(e) = h.run().await {
                    error!(cause = ?e, addr = ?id, "client connection dropped");
                }
                trace!(addr = ?id, "client handler end");
            });
        }
        self.shutdown().await?;
        Ok(())
    }
}

struct QuicStream {
    config: Arc<config::Config>,
    token: CancellationToken,
    active_tunnels: Arc<Mutex<ActiveTunnels>>,
    id: quinn::ConnectionId,
    conn: quinn::Connection,

    handlers: JoinSet<()>,
}
impl QuicStream {
    fn new(
        config: Arc<config::Config>,
        token: CancellationToken,
        active_tunnels: Arc<Mutex<ActiveTunnels>>,
        id: quinn::ConnectionId,
        conn: quinn::Connection,
    ) -> Self {
        QuicStream {
            config,
            token,
            active_tunnels,
            handlers: JoinSet::new(),
            id,
            conn,
        }
    }
    #[tracing::instrument(name = "QuicSupervisor", level = "info", skip_all, fields(bind=self.config.addr.to_string()))]
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                    _ = self.token.cancelled() => {
                        return Ok(());
                    }

                    stream = self.conn.accept_bi() => {
                    let stream = match stream {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                        Ok(s) => s,
                    };
                        let id = stnet::transport::StreamId::Quic(self.id, stream.0.id(), stream.1.id());
                        let b = QuicBox::new(stream.0, stream.1);
                        let mut h = super::ClientHandler::new(
                            self.config.clone(),
                            self.token.child_token(),
                            self.active_tunnels.clone(),
                            (id.clone(), Box::new(b)),
                        );
                        self.handlers.spawn(async move {
                            trace!(addr = ?id, "client handler start");
                            if let Err(e) = h.run().await {
                                error!(cause = ?e, addr = ?id, "client connection dropped");
                            }
                            trace!(addr = ?id, "client handler end");
                        });

                    }

            }
        }
    }
}
