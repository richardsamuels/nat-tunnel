use super::common::*;
use crate::{config::server as config, net as stnet};
use snafu::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

#[derive(Snafu, Debug)]
pub enum ClientValidationError {
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

    js: JoinSet<u16>,
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
        let (tx, rx) = mpsc::channel(config.channel_limits.core);
        let (peer_addr, stream) = stream;
        ClientHandler {
            js: JoinSet::new(),
            peer_addr,
            transport: stnet::Transport::new(config.timeouts.clone(), stream),
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
                password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
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
            let salt = SaltString::generate(&mut OsRng);
            let our_hash = argon2
                .hash_password(self.config.psk.as_bytes(), &salt)
                .map_err(|_| ClientValidationError::IncorrectPSK)?;
            if argon2.verify_password(&key, &our_hash).is_err() {
                return Err(ClientValidationError::IncorrectPSK);
            }
        }
        let frame = stnet::Frame::Auth(key.into());
        self.transport.write_frame(frame).await?;
        Ok(())
    }

    async fn validate_tunnels(&mut self) -> crate::Result<Vec<u16>> {
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

    async fn make_tunnels(&mut self) -> crate::Result<HashMap<u16, tokio::task::AbortHandle>> {
        let tunnels = self.validate_tunnels().await?;

        let mut tunnel_handlers: HashMap<u16, _> = HashMap::new();
        let mut active_tunnels = self.active_tunnels.lock().unwrap();
        tunnels.iter().for_each(|t| {
            let to_client = self.to_client.clone();
            let to_tunnels = self.to_tunnels.clone();
            let port = *t;
            let mtu = self.config.as_ref().mtu;
            let token = self.token.clone();
            let cfg = self.config.clone();
            let h = self.js.spawn(async move {
                trace!(port = ?port, "external listener start");
                let mut h =
                    super::TunnelSupervisor::new(cfg, port, mtu, token, to_tunnels, to_client);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, "tunnel creation error");
                }
                trace!(port = ?port, "external listener end");
                port
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
    pub async fn run(&mut self) -> crate::Result<()> {
        use tokio::time;

        if let Err(e) = self.auth().await {
            error!(cause = ?e, "failed to authenticate client");
            self.transport.write_frame(stnet::Frame::Kthxbai).await?;
            return Err(e.into());
        };
        let handlers = self.make_tunnels().await?;
        let mut heartbeat_interval = time::interval(self.config.timeouts.heartbeat_interval);
        // SAFETY: The first .tick() resolves immediately. This ensures
        // that when the loop starts, the next time this interval ticks is
        // heartbeat_interval seconds from now
        heartbeat_interval.tick().await;
        let mut last_recv_heartbeat =
            std::time::Instant::now() + self.config.timeouts.heartbeat_interval;

        let mut inform_client = true;

        let ret = loop {
            // XXX You MUST NOT return in this loop
            tokio::select! {
                _maybe_interval = heartbeat_interval.tick() => {
                    info!("Channel backpressure: from_tunnels: {}/{}", self.from_tunnels.len(), self.config.channel_limits.core);
                    if last_recv_heartbeat.elapsed() > 2*self.config.timeouts.heartbeat_interval {
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
                        self.config.timeouts.write,
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
                                Some(tx) => {
                                    let _ = tx.send(r).await;
                                },
                            }
                        }

                        stnet::Frame::Kthxbai => {
                            info!("client will shutdown");
                            inform_client = false;
                            break Ok(())
                        }

                        f => {
                            error!(frame = ?f, "unexpected frame");
                        }
                    };
                }

                maybe_js = self.js.join_next() => {
                    match maybe_js {
                        None => break Ok(()), // TODO should this be error?
                        Some(Err(e)) => break Err(e.into()),
                        Some(Ok(port)) => {
                            let mut g = self.active_tunnels.lock().unwrap();
                            g.remove(&port);
                            // This is probably an awful idea
                            // We want the client to be forced to reconnect if any tunnel dies
                            break Ok(());
                        }
                    }
                }

                _ = self.token.cancelled() => {
                    info!("Shutting down client connection");
                    break Ok(())
                }
            }
        };

        if inform_client {
            if let Err(e) = self.transport.write_frame(stnet::Frame::Kthxbai).await {
                error!(e=?e, "failed to inform client of shutdown");
            }
        }
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
        info!("ending stream");
        ret
    }
}
