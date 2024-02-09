use tokio::net as tnet;
use crate::{net as stnet, config};
use tokio_util::codec;
use tokio_serde::Framed;
use crate::{Result, Error};
use std::net::SocketAddr;
use tracing::{error, info};
use futures::TryStreamExt;
use std::sync::{RwLock, Arc};
use tokio::sync::mpsc;
use futures::stream::FuturesUnordered;
use futures::{StreamExt, SinkExt};
use std::ops::Deref;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use std::collections::{HashSet, HashMap};


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
            connman: Arc::new(ConnMan::new().into())
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let (socket, addr) = match self.listener.accept().await {
                Err(e) => {
                    error!(cause = ?e, "Failed to accept new client");
                    continue
                },
                Ok(s) => s
            };
            info!(addr = ?addr, "new client");

            let mut h = ClientHandler::new(self.config.clone(), self.connman.clone(), socket);

            tokio::spawn(async move {
                if let Err(e) = h.run().await {
                    error!(cause = ?e, "client connection dropped");
                }
            });
        }
    }
}

struct ClientHandler {
    transport: stnet::Framed,
    config: Arc<RwLock<config::ServerConfig>>,
    connman: ArchConnMan,
}

impl ClientHandler {
    fn new(config: Arc<RwLock<config::ServerConfig>>, connman: ArchConnMan, stream: tnet::TcpStream) -> ClientHandler {
        ClientHandler{
            transport: stnet::frame(stream),
            connman,
            config,
        }
    }

    async fn read_frame(&mut self) -> Result<stnet::Frame> {
        match self.transport.try_next().await {
            Err(e) => {
                return Err(e.into());
            }
            Ok(None) => {
                return Err(Box::new(stnet::Error::ConnectionDead));
            }
            Ok(Some(frame)) => Ok(frame),
        }
    }

    async fn run(&mut self) -> Result<()> {
        let addr = self.transport.get_ref().get_ref().peer_addr()?;
        let frame = self.read_frame().await?;
        if let stnet::Frame::Auth(auth) = frame {
            let c = self.config.read().unwrap();
            if c.psk != auth.0 {
                // TODO: constant time compare
                error!("Incorrect PSK from {}", addr);
                return Err(format!("Incorrect PSK from {}", addr).into());
            }

        } else {
            error!(addr = ?addr, "Client did not attempt auth");
            return Err("Client did not attempt auth".into());
        };

        let frame = self.read_frame().await?;
        let mut receivers = Vec::new();
        let j_handlers = FuturesUnordered::new();
        if let stnet::Frame::Tunnels(tunnels) = frame {
            let mut connman = self.connman.lock().unwrap();
            for t in &tunnels {
                if connman.tunnels.contains(&t) {
                    error!(port = t, addr = ?addr, "Client sent configuration with duplicate port");
                    return Err("Client sent configuration with duplicate port".into());
                }
            }
            for t in &tunnels {
                let bind_addr: SocketAddr = format!("0.0.0.0:{}", &t).parse().unwrap();
                let listener = tnet::TcpListener::bind(bind_addr).await?;

                info!(port = &t, "Binding new tunnel");
                connman.tunnels.insert(*t);
                let (tunnel_tx, tunnel_rx) = mpsc::channel(16);
                receivers.push(tunnel_rx);

                let port = t.clone();
                let c = self.config.clone();
                j_handlers.push(tokio::spawn(async move {
                    let mut h = TunnelHandler::new(c, listener, tunnel_tx);

                    if let Err(e) = h.run().await {
                        error!(cause = ?e, port = port, "tunnel experienced error");
                    }
                }));

            }

        } else {
            error!(addr = ?addr, "Client did not send tunnel config");
            return Err("Client did not send tunnel config".into());
        };

        let mut t_futures = FuturesUnordered::new();
        for recv in &mut receivers {
            t_futures.push(recv.recv());
        }

        loop {
            tokio::select! {
                tunnel_msg = t_futures.next() => {
                    let tunnel_msg = tunnel_msg.unwrap().unwrap(); // TODO WTF?
                    self.transport.send(stnet::Frame::Dial(tunnel_msg)).await?;
                }
            };
        }
    }
}

struct TunnelHandler {
    listener: tnet::TcpListener,
    tunnel_tx: mpsc::Sender<stnet::PlzDial>,
    config: Arc<RwLock<config::ServerConfig>>,
}

impl TunnelHandler {
    fn new(config: Arc<RwLock<config::ServerConfig>>, listener: tnet::TcpListener, sender: mpsc::Sender<stnet::PlzDial>) -> TunnelHandler {
        TunnelHandler { config, listener, tunnel_tx: sender }
    }

    async fn run(&mut self) -> Result<()> {
        let (a_stream, a_addr) = self.listener.accept().await?;
        let remote_port = a_stream.local_addr()?;
        info!(addr = ?a_addr, port = ?remote_port.port(), "incoming connection");

        let client_listener = tnet::TcpListener::bind("0.0.0.0:0").await?;
        let cl_port = client_listener.local_addr().unwrap().port();
        let dial_request = stnet::PlzDial {
            remote_port: remote_port.port(), via_port: cl_port,
        };
        self.tunnel_tx.send(dial_request).await?;
        loop {
            let (client_stream, client_addr) = match client_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!(port = ?remote_port, cause = ?e, "failed to accept listener");
                    continue
                }
            };

            let mut transport = stnet::frame(client_stream);
            let psk = match transport.next().await {
                Some(Ok(stnet::Frame::Auth(psk))) => psk,
                Some(Ok(_)) => {
                    error!(port = ?remote_port, addr = ?client_addr, "client did not send auth frame");
                    continue
                }
                Some(Err(e)) => {
                    error!(port = ?remote_port, cause = ?e, addr = ?client_addr, "failed to read auth packet");
                    continue
                }
                None => {
                    error!(port = ?remote_port, addr = ?client_addr, "received no data from client");
                    continue
                }
            };

            {
                let c = self.config.read().unwrap();
                if psk.deref() != &c.psk {
                    error!(port = ?remote_port, addr = ?client_addr, "Wrong PSK supplied to redirector");
                    continue
                }
            }

            let client_stream = transport.into_inner().into_inner();

            tokio::spawn(async move {
                let mut h = RedirectorHandler::new(a_stream, client_stream);
                if let Err(e) = h.run().await {
                    error!(cause = ?e, "failed to redirect");
                }
            });

            break;
        }

        Ok(())
    }
}

struct RedirectorHandler {
    left: tnet::TcpStream,
    right: tnet::TcpStream,
}

impl RedirectorHandler {
    fn new(left: tnet::TcpStream, right: tnet::TcpStream) -> Self {
        RedirectorHandler { left, right }
    }

    async fn run(&mut self) -> Result<()> {
        use tokio::io::{BufWriter, BufReader};

        // Yield for writability on both sockets
        self.left.writable().await?;
        self.right.writable().await?;

        let (left_r, left_w) = self.left.split();
        let (right_r, right_w) = self.right.split();

        // TODO 1500 is the default ethernet payload size, but MTU
        // can vary so maybe parameterize this
        let mut left_reader = BufReader::with_capacity(1500, left_r);
        let mut left_writer = BufWriter::with_capacity(1500, left_w);
        let mut right_reader = BufReader::with_capacity(1500, right_r);
        let mut right_writer = BufWriter::with_capacity(1500, right_w);

        loop {
            tokio::select! {
                lr = read_write(&mut left_reader, &mut right_writer) => {
                    match lr {
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from left to right");
                            continue
                        },
                        Ok(0) => break,
                        Ok(_) => continue
                    }
                }
                rl = read_write(&mut right_reader, &mut left_writer) => {
                    match rl {
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from right to left");
                            continue
                        },
                        Ok(0) => break,
                        Ok(_) => continue
                    }
                }
            };
        }

        Ok(())
    }
}

async fn read_write<T, U>(from: &mut T, to: &mut U) -> std::io::Result<usize>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncBufReadExt + std::marker::Unpin,
    U: tokio::io::AsyncWriteExt + std::marker::Unpin,
{
    let buf = from.fill_buf().await?;
    let len = buf.len();
    // len 0 indicates closed sockets
    if len != 0 {
        match to.write(buf).await {
            Err(e) => {
                error!(cause = ?e, "Failed to write");
                return Err(e);
            }
            Ok(_) => {
                from.consume(len);
                to.flush().await?;
            }
        };
    }
    Ok(len)
}

struct ConnMan {
    /// listeners bound on the remote for requests from `A`s
    tunnels: HashSet<u16>,
    clients: HashMap<SocketAddr, stnet::Framed>,
}

impl ConnMan {
    fn new() -> Self {
        ConnMan{
            tunnels: HashSet::new(),
            clients: HashMap::new(),
        }
    }
}

type ArchConnMan = Arc<std::sync::Mutex<ConnMan>>;
