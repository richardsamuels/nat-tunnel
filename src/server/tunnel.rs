use super::common::*;
use crate::{net as stnet, net::Result, redirector::Redirector};
use snafu::ResultExt;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::{net as tnet, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

pub struct TunnelSupervisor {
    config: Arc<crate::config::server::Config>,
    remote_port: u16,
    mtu: u16,
    token: CancellationToken,
    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    tunnels: Arc<Mutex<TunnelChannels>>,
    js: JoinSet<()>,
}

impl TunnelSupervisor {
    pub fn new(
        config: Arc<crate::config::server::Config>,
        remote_port: u16,
        mtu: u16,
        token: CancellationToken,
        tunnels: Arc<Mutex<TunnelChannels>>,
        to_client: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        TunnelSupervisor {
            config,
            remote_port,
            mtu,
            token,
            tunnels,
            to_client,
            js: JoinSet::new(),
        }
    }

    async fn run2(&mut self, external_listener: tnet::TcpListener) -> Result<()> {
        loop {
            let (external_stream, external_addr) = tokio::select! {
                maybe_accept = external_listener.accept() => match maybe_accept{
                    Err(e) => {
                        error!(cause = ?e, "failed to accept client");
                        // This typically means an exhaustion of client ports
                        // so give it a few seconds
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue
                    }
                    Ok(s) => s,
                },

                _ = self.token.cancelled() => break Ok(()),
            };

            info!(port = self.remote_port, external_addr = ?external_addr, "incoming connection");
            if let Err(e) = self
                .to_client
                .send(stnet::RedirectorFrame::StartListener(
                    external_addr,
                    self.remote_port,
                ))
                .await
            {
                error!(e=?e, "failed to send via channel");
                break Err(stnet::Error::ConnectionDead);
            }

            let (to_tunnel, from_client) =
                mpsc::channel::<stnet::RedirectorFrame>(self.config.channel_limits.core);
            {
                let mut tunnels = self.tunnels.lock().unwrap();
                tunnels.insert(external_addr, to_tunnel);
            }

            let tunnels = self.tunnels.clone();
            let mut r = Redirector::with_stream(
                external_addr,
                self.remote_port,
                self.mtu,
                self.token.clone(),
                external_stream,
                self.to_client.clone(),
                from_client,
            );
            let port = self.remote_port;
            self.js.spawn(async move {
                r.run().await;
                let mut tunnels = tunnels.lock().unwrap();
                tunnels.remove(&external_addr);
                trace!(port = port, external_addr = ?external_addr, "connection closed");
            });
        }
    }

    #[tracing::instrument(name = "TunnelSupervisor", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        // TODO support more protocols, including TCP+TLS/QUIC
        let external_listener = tnet::TcpListener::bind(format!("127.0.0.1:{}", self.remote_port))
            .await
            .with_context(|_| crate::net::IoSnafu {
                message: "bind failed",
            })?;

        let ret = self.run2(external_listener).await;

        self.js.shutdown().await;
        while self.js.join_next().await.is_some() {
            // intentionally blank
        }

        ret
    }
}
