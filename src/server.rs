use crate::{config, net as stnet, redirector::Redirector, Result};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::{error, info, trace};

type TunnelChannels = HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>;
type ActiveTunnels = HashSet<u16>;

pub struct Server {
    listener: tnet::TcpListener,
    config: Arc<config::ServerConfig>,
    active_tunnels: Arc<Mutex<ActiveTunnels>>,
}

impl Server {
    pub fn new(config: config::ServerConfig, listener: tnet::TcpListener) -> Self {
        Server {
            listener,
            config: config.into(),
            active_tunnels: Arc::new(ActiveTunnels::new().into()),
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let (socket, addr) = match self.listener.accept().await {
                Err(e) => {
                    error!(cause = ?e, "Failed to accept new client");
                    continue;
                }
                Ok(s) => s,
            };

            let c = self.config.clone();
            let active_tunnels = self.active_tunnels.clone();
            tokio::spawn(async move {
                trace!(addr = ?addr, "client handler start");
                let mut h = ClientHandler::new(c, active_tunnels, socket);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, addr = ?addr, "client connection dropped");
                }
                trace!(addr = ?addr, "client handler end");
            });
        }
    }
}

struct ClientHandler {
    transport: stnet::Transport,
    config: Arc<config::ServerConfig>,

    active_tunnels: Arc<Mutex<ActiveTunnels>>,

    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    from_tunnels: mpsc::Receiver<stnet::RedirectorFrame>,
    to_tunnels: Arc<Mutex<TunnelChannels>>,
}

impl ClientHandler {
    fn new(
        config: Arc<config::ServerConfig>,
        active_tunnels: Arc<Mutex<ActiveTunnels>>,
        stream: tnet::TcpStream,
    ) -> ClientHandler {
        let (tx, rx) = mpsc::channel(128);
        ClientHandler {
            transport: stnet::Transport::new(stream),
            active_tunnels,
            config,
            to_tunnels: Arc::new(HashMap::new().into()),
            to_client: tx,
            from_tunnels: rx,
        }
    }

    /// Validate the client and create external listeners
    async fn auth(&mut self) -> Result<()> {
        let addr = self.transport.peer_addr()?;
        info!(addr = ?addr, "accepted connection from client");

        let frame = self.transport.read_frame().await?;
        {
            let auth = match frame {
                stnet::Frame::Auth(ref auth) => auth,
                _ => return Err(stnet::Error::UnexpectedFrame),
            };

            if self.config.psk != auth.0 {
                // TODO: constant time compare required.
                return Err(format!("Incorrect PSK from {:?}", addr).into());
            }
        }
        self.transport.write_frame(frame).await?; // ack the auth
        Ok(())
    }

    async fn validate_tunnels(&mut self) -> Result<Vec<u16>> {
        let tunnels = match self.transport.read_frame().await? {
            stnet::Frame::Tunnels(t) => t,
            _ => return Err("client did not send tunnel config".to_string().into()),
        };

        let bad_tunnels: Vec<_> = {
            let active_tunnels = self.active_tunnels.lock().unwrap();
            tunnels
                .iter()
                .filter(|x| active_tunnels.contains(x))
                .collect()
        };

        if !bad_tunnels.is_empty() {
            self.transport.write_frame(stnet::Frame::Kthxbai).await?;
            return Err(format!(
                "client sent configuration with remote_port {:?}, which is already in use",
                bad_tunnels
            )
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
            let h = tokio::spawn(async move {
                trace!(port = ?port, "external listener start");
                let mut h = ExternalListener::new(port, to_tunnels, to_client);
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

    async fn run(&mut self) -> Result<()> {
        if let Err(e) = self.auth().await {
            error!(cause = ?e, addr = ?self.transport.peer_addr(), "failed to authenticate client");
            self.transport.write_frame(stnet::Frame::Kthxbai).await?;
        };
        let handlers = self.make_tunnels().await?;

        loop {
            tokio::select! {
                // Redirect data from tunnel to client
                maybe_rx = self.from_tunnels.recv() => {
                    let rframe = match maybe_rx {
                        None => break,
                        Some(data) => data,
                    };
                    self.transport.write_frame(rframe.into()).await?;
                }

                // Read from network
                maybe_frame = self.transport.read_frame() => {
                    trace!(frame = ?maybe_frame, "FRAME");
                    let frame = match maybe_frame {
                        Err(stnet::Error::ConnectionDead) => break,
                        Err(e) => {
                            error!(cause = ?e, addr = ?self.transport.peer_addr(), "failed reading frame from network");
                            break
                        }
                        Ok(f) => f,
                    };
                    match frame {
                        stnet::Frame::Redirector(r) => {
                            let id = match r {
                                stnet::RedirectorFrame::Datagram(ref d) => d.id,
                                stnet::RedirectorFrame::KillListener(id) => id,
                            };
                            match self.get_tunnel_tx(id) {
                                None => error!(addr = ?id, "no channel for port"),
                                Some(tx) => tx.send(r).await?,
                            }
                        }

                        stnet::Frame::Kthxbai => break,
                        f => {
                            error!(frame = ?f, "unexpected frame");
                        }
                    };
                }
            }
        }

        let mut active_tunnels = self.active_tunnels.lock().unwrap();
        info!(tunnels = ?active_tunnels.iter(), "cleaning up tunnels");
        for (t, h) in handlers.iter() {
            h.abort();
            active_tunnels.remove(t);
        }
        Ok(())
    }
}

struct ExternalListener {
    remote_port: u16,
    to_client: mpsc::Sender<stnet::RedirectorFrame>,
    tunnels: Arc<Mutex<TunnelChannels>>,
}

impl ExternalListener {
    fn new(
        remote_port: u16,
        tunnels: Arc<Mutex<TunnelChannels>>,
        to_client: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        ExternalListener {
            remote_port,
            tunnels,
            to_client,
        }
    }
    async fn run(&mut self) -> Result<()> {
        let external_listener =
            tnet::TcpListener::bind(format!("127.0.0.1:{}", self.remote_port)).await?;
        loop {
            let (external_stream, external_addr) = external_listener.accept().await?;
            info!(port = self.remote_port, external_addr = ?external_addr, "incoming connection");

            let (to_tunnel, from_client) = mpsc::channel::<stnet::RedirectorFrame>(32);
            {
                let mut tunnels = self.tunnels.lock().unwrap();
                tunnels.insert(external_addr, to_tunnel);
            }

            let port = self.remote_port;
            let to_client = self.to_client.clone();
            let tunnels = self.tunnels.clone();
            tokio::spawn(async move {
                let mut r = Redirector::with_stream(
                    external_addr,
                    port,
                    external_stream,
                    to_client,
                    from_client,
                );
                let _ = r.run().await;
                let mut tunnels = tunnels.lock().unwrap();
                tunnels.remove(&external_addr);
                trace!(addr = ?external_addr, "Tunnel done");
            });
        }
    }
}
