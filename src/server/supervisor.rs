use crate::server::common::*;
use crate::{config::server as config, net as stnet, redirector::Redirector, Result};
use snafu::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

#[derive(Snafu, Debug)]
enum ClientValidationError {
    #[snafu(display(
        "client sent configuration with remote_ports {tunnels:?}, which are already in use"
    ))]
    DuplicateTunnels { tunnels: Vec<u16> },
    #[snafu(display("Incorrect PSK from client"))]
    IncorrectPSK,
    #[snafu(display("transport error: {source}"))]
    TransportError { source: stnet::Error },
}

impl std::convert::From<stnet::Error> for ClientValidationError {
    fn from(value: stnet::Error) -> Self {
        ClientValidationError::TransportError { source: value }
    }
}

type ClientResult<T> = std::result::Result<T, ClientValidationError>;

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

    #[tracing::instrument(name = "Supervisor", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        if self.tls.is_some() {
            info!("TLS enabled. All connections to Clients will be encrypted.");
        } else {
            warn!("TLS *DISABLED*. All data is transmitted in the clear.");
        }
        loop {
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
                    return Ok(())
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
                let mut h = ClientHandler::new(
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
                let mut h = ClientHandler::new(
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
        }
    }
}

pub struct ClientHandler<T>
where
    T: stnet::Stream,
{
    peer_addr: stnet::StreamId,
    config: Arc<config::Config>,
    token: CancellationToken,

    transport: stnet::Transport<T>,

    active_tunnels: Arc<Mutex<ActiveTunnels>>,

    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    from_tunnels: mpsc::Receiver<stnet::RedirectorFrame>,
    to_tunnels: Arc<Mutex<TunnelChannels>>,
}

impl<T> ClientHandler<T>
where
    T: stnet::Stream,
{
    pub fn new(
        config: Arc<config::Config>,
        token: CancellationToken,
        active_tunnels: Arc<Mutex<ActiveTunnels>>,
        stream: stnet::AcceptedStream<T>,
    ) -> ClientHandler<T> {
        let (tx, rx) = mpsc::channel(128);
        let (peer_addr, stream) = stream;
        ClientHandler {
            peer_addr,
            transport: stnet::Transport::new(stream),
            token,
            active_tunnels,
            config,
            to_tunnels: Arc::new(HashMap::new().into()),
            to_client: tx,
            from_tunnels: rx,
        }
    }

    /// Validate the client and create external listeners
    async fn auth(&mut self) -> ClientResult<()> {
        info!(addr = ?self.peer_addr, "accepted connection from client");

        let key = self.transport.read_helo().await?;

        {
            use argon2::{
                password_hash::{PasswordHasher, PasswordVerifier, SaltString},
                Argon2,
            };
            let argon2 = Argon2::default();

            // We do a quick hack job of hashing the psk so that the psk lengths
            // are guaranteed to be the same and then use verify_password
            // to perform constant time comparison. If we didn't do this,
            // constant_time_eq would return false immediately on dissimilar
            // lengths, which could reveal key length
            //
            // TODO We should probably support encoding the PSK on disk as
            // a PHC string with randomly generated salt.
            let lolsalt = SaltString::from_b64("dontcaredontcaredontcare").unwrap();
            let our_hash = argon2
                .hash_password(self.config.psk.as_bytes(), &lolsalt)
                .map_err(|_| ClientValidationError::IncorrectPSK)?;
            if argon2.verify_password(&key, &our_hash).is_err() {
                return Err(ClientValidationError::IncorrectPSK);
            }
        }
        let frame = stnet::Frame::Auth(key);
        self.transport.write_frame(frame).await?;
        Ok(())
    }

    async fn validate_tunnels(&mut self) -> Result<Vec<u16>> {
        let tunnels = match self.transport.read_frame().await? {
            stnet::Frame::Tunnels(t) => t,
            _ => return Err(stnet::Error::UnexpectedFrame.into()),
        };

        let bad_tunnels: Vec<u16> = {
            let active_tunnels = self.active_tunnels.lock().unwrap();
            tunnels
                .iter()
                .filter(|x| active_tunnels.contains(x))
                .cloned()
                .collect()
        };

        if !bad_tunnels.is_empty() {
            self.transport.write_frame(stnet::Frame::Kthxbai).await?;
            return Err(ClientValidationError::DuplicateTunnels {
                tunnels: bad_tunnels,
            }
            .into());
        }
        self.transport
            .write_frame(stnet::Frame::Tunnels(tunnels.clone()))
            .await?; // Ack the config

        Ok(tunnels)
    }

    async fn make_tunnels(&mut self) -> Result<HashMap<u16, tokio::task::JoinHandle<()>>> {
        let tunnels = self.validate_tunnels().await?;

        let mut tunnel_handlers: HashMap<u16, _> = HashMap::new();
        let mut active_tunnels = self.active_tunnels.lock().unwrap();
        tunnels.iter().for_each(|t| {
            let to_client = self.to_client.clone();
            let to_tunnels = self.to_tunnels.clone();
            let port = *t;
            let mtu = self.config.as_ref().mtu;
            let token = self.token.clone();
            let h = tokio::spawn(async move {
                trace!(port = ?port, "external listener start");
                let mut h = ExternalListener::new(port, mtu, token, to_tunnels, to_client);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, "tunnel creation error");
                }
                trace!(port = ?port, "external listener end");
            });
            tunnel_handlers.insert(port, h);
            active_tunnels.insert(port);
        });
        Ok(tunnel_handlers)
    }

    fn get_tunnel_tx(&self, id: SocketAddr) -> Option<mpsc::Sender<stnet::RedirectorFrame>> {
        let to_tunnels = self.to_tunnels.lock().unwrap();
        to_tunnels.get(&id).cloned()
    }

    #[tracing::instrument(name = "Server", level = "info", skip_all)]
    pub async fn run(&mut self) -> Result<()> {
        use std::time::Duration;
        use tokio::time;

        if let Err(e) = self.auth().await {
            error!(cause = ?e, "failed to authenticate client");
            self.transport.write_frame(stnet::Frame::Kthxbai).await?;
        };
        let handlers = self.make_tunnels().await?;
        let mut heartbeat_interval = time::interval(Duration::from_secs(60));
        // SAFETY: The first .tick() resolves immediately. This ensures
        // that when the loop starts, the next time this interval ticks is
        // 60 seconds from now
        heartbeat_interval.tick().await;
        let mut last_recv_heartbeat =
            std::time::Instant::now() + std::time::Duration::from_secs(60);

        let ret = loop {
            // XXX You MUST NOT return in this loop
            tokio::select! {
                _maybe_interval = heartbeat_interval.tick() => {
                    if last_recv_heartbeat.elapsed().as_secs() > 60 {
                        error!("Missing heartbeat from client. Killing connection");
                        break Err(stnet::Error::ConnectionDead.into());
                    }

                    if let Err(e) = self.transport.write_frame(stnet::Frame::Heartbeat).await {
                        error!(e = ?e, "failed to send heartbeat");
                        break Err(e.into());
                    }
                    trace!("sent heartbeat to client");
                }

                maybe_rx = self.from_tunnels.recv() => {
                    let rframe = match maybe_rx {
                        None => break Ok(()),
                        Some(data) => data,
                    };
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        self.transport.write_frame(rframe.into())
                    ).await {
                        Ok(Ok(_)) => (),
                        Ok(Err(e)) => break Err(e.into()),
                        Err(_) => {
                            error!("Write operation timed out");
                            break Err(stnet::Error::ConnectionDead.into());
                        }
                    }
                }

                // Read from network
                maybe_frame = self.transport.read_frame() => {
                    trace!(frame = ?maybe_frame, "FRAME");
                    let frame = match maybe_frame {
                        Err(stnet::Error::ConnectionDead) => {
                            error!(addr = ?self.peer_addr, "connection is dead");
                            break Err(stnet::Error::ConnectionDead.into())
                        },
                        Err(e) => {
                            error!(cause = ?e, addr = ?self.peer_addr, "failed reading frame from network");
                            break Err(e.into())
                        }
                        Ok(f) => f,
                    };
                    match frame {
                        stnet::Frame::Heartbeat => {
                            trace!("heartbeat received from client");
                            last_recv_heartbeat = std::time::Instant::now();
                        }

                        stnet::Frame::Redirector(r) => {
                            if let stnet::RedirectorFrame::KillListener(ref id) = r {
                                let mut to_tunnels = self.to_tunnels.lock().unwrap();
                                to_tunnels.remove(id);
                                continue
                            }
                            let id = r.id();
                            match self.get_tunnel_tx(*id) {
                                None => error!(addr = ?id, "no channel for port. connection already killed?"),
                                Some(tx) => tx.send(r).await?,
                            }
                        }

                        stnet::Frame::Kthxbai => {
                            info!("client will shutdown");
                            break Ok(())
                        }

                        f => {
                            error!(frame = ?f, "unexpected frame");
                        }
                    };
                }

                _ = self.token.cancelled() => {
                    self.transport.write_frame(stnet::Frame::Kthxbai).await?;
                    info!("Shutting down client connection");
                    break Ok(())
                }
            }
        };

        {
            let mut active_tunnels = self.active_tunnels.lock().unwrap();
            trace!(tunnels = ?active_tunnels.iter(), "cleaning up tunnels");
            for (t, h) in handlers.iter() {
                h.abort();
                active_tunnels.remove(t);
            }
            let mut tunnels = self.to_tunnels.lock().unwrap();
            tunnels.clear();
        }
        ret
    }
}

struct ExternalListener {
    remote_port: u16,
    mtu: u16,
    token: CancellationToken,
    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    tunnels: Arc<Mutex<TunnelChannels>>,
}

impl ExternalListener {
    fn new(
        remote_port: u16,
        mtu: u16,
        token: CancellationToken,
        tunnels: Arc<Mutex<TunnelChannels>>,
        to_client: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        ExternalListener {
            remote_port,
            mtu,
            token,
            tunnels,
            to_client,
        }
    }

    #[tracing::instrument(name = "External", level = "info", skip_all)]
    async fn run(&mut self) -> Result<()> {
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
