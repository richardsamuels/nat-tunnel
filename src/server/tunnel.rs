use super::common::*;
use crate::{net as stnet, redirector::Redirector, Result};
use std::sync::{Arc, Mutex};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

pub struct TunnelSupervisor {
    remote_port: u16,
    mtu: u16,
    token: CancellationToken,
    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    tunnels: Arc<Mutex<TunnelChannels>>,
}

impl TunnelSupervisor {
    pub fn new(
        remote_port: u16,
        mtu: u16,
        token: CancellationToken,
        tunnels: Arc<Mutex<TunnelChannels>>,
        to_client: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        TunnelSupervisor {
            remote_port,
            mtu,
            token,
            tunnels,
            to_client,
        }
    }

    #[tracing::instrument(name = "TunnelSupervisor", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        // TODO support more protocols, including TCP+TLS/QUIC
        let external_listener =
            tnet::TcpListener::bind(format!("127.0.0.1:{}", self.remote_port)).await?;
        loop {
            let (external_stream, external_addr) = tokio::select! {
                maybe_accept = external_listener.accept() => match maybe_accept{
                    Err(e) => {
                        error!(cause = ?e, "failed to accept client");
                        continue
                    }
                    Ok(s) => s,
                },

                _ = self.token.cancelled() => break Ok(()),
            };

            info!(port = self.remote_port, external_addr = ?external_addr, "incoming connection");
            self.to_client
                .send(stnet::RedirectorFrame::StartListener(
                    external_addr,
                    self.remote_port,
                ))
                .await?;

            let (to_tunnel, from_client) = mpsc::channel::<stnet::RedirectorFrame>(32);
            {
                let mut tunnels = self.tunnels.lock().unwrap();
                tunnels.insert(external_addr, to_tunnel);
            }

            let port = self.remote_port;
            let mtu = self.mtu;
            let to_client = self.to_client.clone();
            let tunnels = self.tunnels.clone();
            let token = self.token.clone();
            tokio::spawn(async move {
                let mut r = Redirector::with_stream(
                    external_addr,
                    port,
                    mtu,
                    token,
                    external_stream,
                    to_client,
                    from_client,
                );
                r.run().await;
                let mut tunnels = tunnels.lock().unwrap();
                tunnels.remove(&external_addr);
                trace!(addr = ?external_addr, "Tunnel done");
            });
        }
    }
}
