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
use tracing::{error, info};

use std::collections::{HashMap, HashSet};

pub struct Remote {
    listener: tnet::TcpListener,
    config: Arc<RwLock<config::ServerConfig>>,
    connman: ArchConnMan,
}

impl Remote {
    pub fn new(config: config::ServerConfig, listener: tnet::TcpListener) -> Self {
        Remote {
            listener,
            config: Arc::new(config.into()),
            connman: Arc::new(ConnMan::new().into()),
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
            let connman = self.connman.clone();
            tokio::spawn(async move {
                let mut h = ClientHandler::new(c, connman, socket);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, addr = ?addr, "client connection dropped");
                }
            });
        }
    }
}

struct ClientHandler {
    transport: stnet::Transport,
    config: Arc<RwLock<config::ServerConfig>>,
    connman: ArchConnMan,

    tx: mpsc::Sender<stnet::Datagram>,
    rx: mpsc::Receiver<stnet::Datagram>,

    tunnel_tx: TunnelHdlr,
}

impl ClientHandler {
    fn new(
        config: Arc<RwLock<config::ServerConfig>>,
        connman: ArchConnMan,
        stream: tnet::TcpStream,
    ) -> ClientHandler {
        let (tx, rx) = mpsc::channel(128);
        ClientHandler {
            transport: stnet::Transport::new(stream),
            connman,
            config,
            tunnel_tx: Arc::new(HashMap::new().into()),
            tx,
            rx,
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

        let mut connman = self.connman.lock().await;
        {
            for t in &tunnels {
                if connman.all.contains(t) {
                    return Err(format!(
                        "client sent configuration with duplicate remote_port {}",
                        &t
                    )
                    .into());
                }
            }
        }

        let handles = tunnels.iter().map(|t| {
            let t = *t;
            let r_tx = self.tx.clone();
            let ttx = self.tunnel_tx.clone();

            let port = t;
            tokio::spawn(async move {
                let mut h = Tunnel::new(port, ttx, r_tx);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, "tunnel creation error");
                }
            })
        });
        tunnels.iter().zip(handles).for_each(|x| {
            let (port, h) = x;
            handlers.insert(*port, h);
            connman.all.insert(*port);
        });
        Ok(handlers)
    }

    async fn run(&mut self) -> Result<()> {
        let handlers = self.auth().await?;

        loop {
            tokio::select! {
                // Read from network
                maybe_rx = self.rx.recv() => {
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
                            let ttx = self.tunnel_tx.lock().await;
                            let tx = match ttx.get(&d.id) {
                                None => {
                                    error!(addr = ?d.id, "no channel for port");
                                    break
                                }
                                Some(tx) => tx
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

        let mut connman = self.connman.lock().await;
        info!(tunnels = ?connman.tx.keys(), "cleaning up tunnels");
        for (t, h) in handlers.iter() {
            h.abort();
            connman.tx.remove(t);
            connman.rx.remove(t);
        }
        Ok(())
    }
}

type TunnelHdlr = Arc<tokio::sync::Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::Datagram>>>>;

struct Tunnel {
    remote_port: u16,
    client_tx: mpsc::Sender<stnet::Datagram>,

    tunnel_tx: TunnelHdlr,
}

impl Tunnel {
    fn new(
        remote_port: u16,
        tunnel_tx: TunnelHdlr,
        client_tx: mpsc::Sender<stnet::Datagram>,
    ) -> Self {
        Tunnel {
            remote_port,
            client_tx,
            tunnel_tx,
        }
    }
    async fn run(&mut self) -> Result<()> {
        let a_listener = tnet::TcpListener::bind(format!("127.0.0.1:{}", self.remote_port)).await?;
        loop {
            let (a_stream, a_addr) = a_listener.accept().await?;
            info!(port = self.remote_port, a_addr = ?a_addr, "incoming connection");

            let (handler_tx, handler_rx) = mpsc::channel::<stnet::Datagram>(32);
            {
                let mut tu = self.tunnel_tx.lock().await;
                tu.insert(a_addr.clone(), handler_tx);
            }

            let port = self.remote_port.clone();
            let c_tx = self.client_tx.clone();
            let ttx = self.tunnel_tx.clone();
            tokio::spawn(async move {
                let mut h = TunnelHandler::new(port, a_stream, c_tx, handler_rx);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, port = port, addr = ?a_addr, "error redirecting");
                }
                let mut tu = ttx.lock().await;
                tu.remove(&a_addr);
            });
        }
    }
}

struct TunnelHandler {
    remote_port: u16,
    stream: tnet::TcpStream,
    data_tx: mpsc::Sender<stnet::Datagram>,
    data_rx: mpsc::Receiver<stnet::Datagram>,
}

impl TunnelHandler {
    fn new(
        remote_port: u16,
        stream: tnet::TcpStream,
        data_tx: mpsc::Sender<stnet::Datagram>,
        data_rx: mpsc::Receiver<stnet::Datagram>,
    ) -> TunnelHandler {
        TunnelHandler {
            remote_port,
            stream,
            data_tx,
            data_rx,
        }
    }

    async fn run(&mut self) -> Result<()> {
        'outer: loop {
            let a_addr = self.stream.peer_addr()?;

            let (a_reader, a_writer) = self.stream.split();

            let mut a_reader = BufReader::with_capacity(1500, a_reader);
            let mut a_writer = BufWriter::with_capacity(1500, a_writer);

            loop {
                tokio::select! {
                    // Read from network (a)
                    maybe_buf = a_reader.fill_buf() => {
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
                        self.data_tx.send(d).await?;
                        a_reader.consume(len);
                    }

                    // Read from channel (network)
                    maybe_data = self.data_rx.recv() => {
                        let data: stnet::Datagram = match maybe_data {
                            None => break 'outer,
                            Some(data) => data,
                        };
                        a_writer.write_all(&data.data).await?;
                        a_writer.flush().await?;
                    }
                }
            }
        }

        Ok(())
    }
}

struct ConnMan {
    /// listeners bound on the remote for requests from `A`s
    tx: HashMap<u16, mpsc::Sender<stnet::Datagram>>,
    rx: HashMap<u16, mpsc::Receiver<stnet::Datagram>>,
    all: HashSet<u16>,
}

impl ConnMan {
    fn new() -> Self {
        ConnMan {
            tx: HashMap::new(),
            rx: HashMap::new(),
            all: HashSet::new(),
        }
    }
}

type ArchConnMan = Arc<tokio::sync::Mutex<ConnMan>>;
