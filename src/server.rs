use crate::Result;
use crate::{config, net as stnet};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use futures::TryStreamExt;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::{BufReader, BufWriter};

use futures::Future;
use futures::SinkExt;
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::{error, info, trace};

use std::collections::{HashMap, HashSet};

pub struct Server {
    listener: tnet::TcpListener,
    config: Arc<RwLock<config::ServerConfig>>,
    active_tunnels: ArcMActiveTunnels,
}

impl Server {
    pub fn new(config: config::ServerConfig, listener: tnet::TcpListener) -> Self {
        Server {
            listener,
            config: Arc::new(config.into()),
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
    config: Arc<RwLock<config::ServerConfig>>,
    active_tunnels: ArcMActiveTunnels,

    to_client: mpsc::Sender<stnet::Datagram>,
    from_tunnels: mpsc::Receiver<stnet::Datagram>,

    to_tunnels: TunnelHdlr,
}

impl ClientHandler {
    fn new(
        config: Arc<RwLock<config::ServerConfig>>,
        active_tunnels: ArcMActiveTunnels,
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

    async fn auth(&mut self) -> Result<HashMap<u16, tokio::task::JoinHandle<()>>> {
        let addr = self.transport.peer_addr()?;
        info!(addr = ?addr, "accepted connection from client");
        let frame = self.transport.read_frame().await?;
        if let stnet::Frame::Auth(auth) = frame {
            let c = self.config.read().unwrap();
            if c.psk != auth.0 {
                // TODO: constant time compare required.
                return Err(format!("Incorrect PSK from {:?}", addr).into());
            }
        } else {
            return Err("expected auth frame, but did not get it".into());
        };

        let tunnels = match self.transport.read_frame().await? {
            stnet::Frame::Tunnels(t) => t,
            _ => return Err("client did not send tunnel config".into()),
        };

        let mut handlers: HashMap<u16, _> = HashMap::new();

        {
            let active_tunnels = self.active_tunnels.lock().unwrap();
            for t in &tunnels {
                if active_tunnels.contains(t) {
                    return Err(format!(
                        "client sent configuration with duplicate remote_port {}",
                        &t
                    )
                    .into());
                }
            }
        }

        let handles = tunnels.iter().map(|t| {
            let to_client = self.to_client.clone();
            let to_tunnels = self.to_tunnels.clone();

            let port = *t;
            tokio::spawn(async move {
                trace!(port = ?port, "tunnel start");
                let mut h = Tunnel::new(port, to_tunnels, to_client);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, "tunnel creation error");
                }
                trace!(port = ?port, "tunnel end");
            })
        });
        let mut active_tunnels = self.active_tunnels.lock().unwrap();
        tunnels.iter().zip(handles).for_each(|x| {
            let (port, h) = x;
            handlers.insert(*port, h);
            active_tunnels.insert(*port);
        });
        Ok(handlers)
    }

    async fn run(&mut self) -> Result<()> {
        let handlers = self.auth().await?;

        loop {
            tokio::select! {
                // Read from network
                maybe_rx = self.from_tunnels.recv() => {
                    let data: stnet::Datagram = match maybe_rx {
                        None => break,
                        Some(data) => data,
                    };
                    self.transport.write_frame(data.into()).await?;
                }
                maybe_frame = self.transport.read_frame() => {
                    let frame = match maybe_frame {
                        Err(stnet::Error::ConnectionDead) => break,
                        Err(e) => return Err(e.into()),
                        Ok(f) => f,
                    };
                    match frame {
                        stnet::Frame::Datagram(d) => {
                            let tx = {
                                let to_tunnels = self.to_tunnels.lock().unwrap();
                                match to_tunnels.get(&d.id) {
                                    None => {
                                        error!(addr = ?d.id, "no channel for port");
                                        break
                                    }
                                    Some(tx) => tx.clone()

                                }
                            };
                            tx.send(d).await?;
                        }
                        stnet::Frame::Kthxbai => break,
                        _ => {
                            error!("unexpected frame");
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

type TunnelHdlr = Arc<std::sync::Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::Datagram>>>>;

struct Tunnel {
    remote_port: u16,
    to_client: mpsc::Sender<stnet::Datagram>,

    to_tunnels: TunnelHdlr,
}

impl Tunnel {
    fn new(
        remote_port: u16,
        to_tunnels: TunnelHdlr,
        to_client: mpsc::Sender<stnet::Datagram>,
    ) -> Self {
        Tunnel {
            remote_port,
            to_tunnels,
            to_client,
        }
    }
    async fn run(&mut self) -> Result<()> {
        let a_listener = tnet::TcpListener::bind(format!("127.0.0.1:{}", self.remote_port)).await?;
        loop {
            let (a_stream, a_addr) = a_listener.accept().await?;
            info!(port = self.remote_port, a_addr = ?a_addr, "incoming connection");

            let (to_tunnel, from_client) = mpsc::channel::<stnet::Datagram>(32);
            {
                let mut tu = self.to_tunnels.lock().unwrap();
                tu.insert(a_addr, to_tunnel);
            }

            let port = self.remote_port;
            let to_client = self.to_client.clone();
            let to_tunnels = self.to_tunnels.clone();
            tokio::spawn(async move {
                trace!(addr = ?a_addr, "Tunnel handler start");
                let mut h = TunnelHandler::new(port, a_stream, to_client, from_client);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, addr = ?a_addr, "error redirecting");
                }
                let mut tu = to_tunnels.lock().unwrap();
                tu.remove(&a_addr);
                trace!(addr = ?a_addr, "Tunnel handler end");
            });
        }
    }
}

struct TunnelHandler {
    remote_port: u16,
    stream: tnet::TcpStream,
    to_client: mpsc::Sender<stnet::Datagram>,
    from_client: mpsc::Receiver<stnet::Datagram>,
}

impl TunnelHandler {
    fn new(
        remote_port: u16,
        stream: tnet::TcpStream,
        to_client: mpsc::Sender<stnet::Datagram>,
        from_client: mpsc::Receiver<stnet::Datagram>,
    ) -> TunnelHandler {
        TunnelHandler {
            remote_port,
            stream,
            to_client,
            from_client,
        }
    }

    async fn run(&mut self) -> Result<()> {
        let a_addr = self.stream.peer_addr()?;

        let (a_reader, a_writer) = self.stream.split();

        let mut a_reader = BufReader::with_capacity(1500, a_reader);
        let mut a_writer = BufWriter::with_capacity(1500, a_writer);

        loop {
            tokio::select! {
                // Read from network (a)
                maybe_buf = a_reader.fill_buf() => {
                    info!(mb = ?maybe_buf,"read");
                    let buf = match maybe_buf {
                        Err(e) => {
                            error!(cause = ?e, "failed to read from `a`");
                            break;
                        },
                        Ok(buf) => buf,
                    };
                    let len = buf.len();
                    let d = stnet::Datagram {
                        id: a_addr,
                        port: self.remote_port,
                        data: buf.to_vec(), // TODO nooooooooooo
                    };
                    info!(data = ?d, "read");
                    a_reader.consume(len);
                    if len == 0 {
                        break;
                    }
                    self.to_client.send(d).await?;
                }

                // Read from channel (network)
                maybe_data = self.from_client.recv() => {
                    info!(md = ?maybe_data, "write");
                    let data: stnet::Datagram = match maybe_data {
                        None => break,
                        Some(data) => data,
                    };
                    info!(data = ?data, "write");
                    if data.data.is_empty() {
                        break;
                    }
                    a_writer.write_all(&data.data).await?;
                    a_writer.flush().await?;
                }
            }
        }
        let _ = a_reader.into_inner();
        let _ = a_writer.into_inner().shutdown().await;

        Ok(())
    }
}

type ActiveTunnels = HashSet<u16>;

type ArcMActiveTunnels= Arc<std::sync::Mutex<ActiveTunnels>>;
