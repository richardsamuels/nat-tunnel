use crate::net::reconnectable_err;
use crate::{config::client as config, net as stnet, net::Frame, redirector::Redirector, Result};
use rustls_pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

pub struct Client<T> {
    peer_addr: stnet::StreamId,
    config: config::Config,
    token: CancellationToken,
    transport: stnet::Transport<T>,

    to_server: mpsc::Sender<stnet::RedirectorFrame>,
    from_internal: mpsc::Receiver<stnet::RedirectorFrame>,
    to_internal: HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>,

    handlers: JoinSet<SocketAddr>,
}

impl<T> Client<T>
where
    T: stnet::Stream,
{
    pub fn new(
        config: config::Config,
        token: CancellationToken,
        peer_addr: stnet::StreamId,
        stream: T,
    ) -> Client<T> {
        let (tx, rx) = mpsc::channel(config.channel_limits.core);
        Client {
            transport: stnet::Transport::new(config.timeouts.clone(), stream),
            peer_addr,
            config,
            token,
            handlers: JoinSet::new(),
            to_server: tx,
            from_internal: rx,
            to_internal: HashMap::new(),
        }
    }

    async fn push_tunnel_config(&mut self) -> Result<()> {
        self.transport.send_helo(self.config.psk.as_bytes()).await?;

        let frame = self.transport.read_frame().await?;
        let stnet::Frame::Auth(_) = frame else {
            return Err(stnet::Error::ConnectionRefused.into());
        };

        let tunnels = self.config.tunnels.keys().copied().collect();
        self.transport.write_frame(Frame::Tunnels(tunnels)).await?;

        let frame = self.transport.read_frame().await?;
        let stnet::Frame::Tunnels(_) = frame else {
            return Err(stnet::Error::ConnectionRefused.into());
        };
        trace!("Pushed tunnel config to remote");
        Ok(())
    }

    pub fn redirector_join(
        &mut self,
        maybe_join: Option<std::result::Result<SocketAddr, JoinError>>,
    ) {
        let addr = match maybe_join {
            // no handlers found just means no active clients
            None => return,

            // Log/swallow panics in redirector as it won't affect anything else
            Some(Err(e)) => {
                error!(cause = ?e, "redirector task panicked");
                return;
            }
            Some(Ok(h)) => h,
        };
        trace!(addr = ?addr, "Cleaned up redirector");
    }

    pub async fn read_frame(&mut self, maybe_frame: stnet::Result<stnet::Frame>) -> Result<()> {
        let frame = match maybe_frame {
            Err(e) => {
                error!(cause = ?e, "failed to read");
                if let stnet::Error::Io { ref source, .. } = e {
                    if reconnectable_err(source) {
                        return Err(stnet::Error::ConnectionDead.into());
                    }
                }
                return Err(e.into());
            }
            Ok(s) => s,
        };

        match frame {
            Frame::Heartbeat => {
                trace!("heartbeat received from server");
                if let Err(e) = self.transport.write_frame(Frame::Heartbeat).await {
                    error!(e=?e, "failed to send heartbeat to server");
                    return Err(e.into());
                }
            }
            Frame::Kthxbai => {
                info!("Server is shutting down");
            }
            Frame::Redirector(r) => {
                if let Err(e) = self.redirector_frame(r).await {
                    error!(cause = ?e, "redirector failed");
                }
            }
            f => {
                trace!(frame = ?f, addr = ?self.peer_addr, "received unexpected frame");
            }
        };
        Ok(())
    }

    #[tracing::instrument(name = "Client", level = "debug", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        self.push_tunnel_config().await?;
        let ret = loop {
            tokio::select! {
                // A tunnel has completed it's redirection
                maybe_join = self.handlers.join_next() => self.redirector_join(maybe_join),

                // Client receives a frame from Server
                maybe_frame = self.transport.read_frame() => {
                    if let Err(e) = self.read_frame(maybe_frame).await {
                        break Err(e)
                    }
                }

                // We have some data to send from a tunnel to the client
                maybe_recv = self.from_internal.recv() => {
                    let data = match maybe_recv {
                        None => continue, // can this ever happen?
                        Some(d) => d,
                    };

                    if let Err(e) = self.transport.write_frame(data.into()).await {
                        break Err(e.into())
                    }
                }

                _ = self.token.cancelled() => {
                    break Ok(());
                }
            }
        };
        self.handlers.abort_all();
        if let Err(e) = self.transport.write_frame(Frame::Kthxbai).await {
            error!(e=?e, "failed to inform server of shutdown");
        }
        while self.handlers.join_next().await.is_some() {}
        ret
    }

    async fn new_redirector<U: stnet::Stream + 'static>(
        &mut self,
        id: SocketAddr,
        port: u16,
        internal_stream: U,
    ) -> Result<()> {
        let to_server = self.to_server.clone();
        let token = self.token.clone();
        let mtu = self.config.mtu;
        let (to_internal, from_internal) = mpsc::channel(self.config.channel_limits.core);
        self.to_internal.insert(id, to_internal);
        self.handlers.spawn(async move {
            let mut r = Redirector::with_stream(
                id,
                port,
                mtu,
                token,
                internal_stream,
                to_server,
                from_internal,
            );
            r.run().await;
            id
        });
        Ok(())
    }

    async fn new_conn(&mut self, id: SocketAddr, port: u16) -> Result<()> {
        let tunnel_cfg = match self.config.tunnels.get(&port) {
            None => unreachable!(),
            Some(p) => p,
        };
        let internal_stream =
            TcpStream::connect((tunnel_cfg.local_hostname.clone(), tunnel_cfg.local_port)).await?;
        let internal_addr = internal_stream.peer_addr().unwrap();
        if let Some(ref crypto_cfg) = tunnel_cfg.crypto {
            info!(internal_addr = ?internal_addr, for_ = ?id, "connecting to Internal (TLS)");
            let cc = crate::tls_self_signed::crypto_client_init(crypto_cfg)?;
            let connector = TlsConnector::from(cc);
            let dnsname = ServerName::try_from(tunnel_cfg.local_hostname.clone())?;
            let tls_stream = connector.connect(dnsname, internal_stream).await?;
            self.new_redirector(id, port, tls_stream).await?;
        } else {
            info!(internal_addr = ?internal_addr, for_ = ?id, "connecting to Internal");
            self.new_redirector(id, port, internal_stream).await?;
        };

        Ok(())
    }

    async fn redirector_frame(&mut self, frame: stnet::RedirectorFrame) -> Result<()> {
        match frame {
            stnet::RedirectorFrame::Datagram(ref _d) => {
                let id = *frame.id();
                let to_internal = match self.to_internal.get(&id) {
                    None => {
                        error!(id = ?id,"no channel");
                        return Ok(());
                    }
                    Some(s) => s,
                };
                match to_internal.send(frame).await {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        self.to_internal.remove(&id);
                        return Ok(());
                    }
                }
            }
            stnet::RedirectorFrame::StartListener(id, port) => {
                // Open a tunnel to the internal if needed
                if !self.to_internal.contains_key(&id) {
                    if let Err(e) = self.new_conn(id, port).await {
                        // make sure the Server kills off the connection on its side
                        let d = stnet::RedirectorFrame::KillListener(id);
                        self.transport.write_frame(d.into()).await?;
                        return Err(e.into());
                    }
                }
            }
            stnet::RedirectorFrame::KillListener(ref id) => {
                self.to_internal.remove(id);
            }
        }

        Ok(())
    }
}
