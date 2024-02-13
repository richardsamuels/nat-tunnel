use crate::{config, net as stnet, net::Frame, redirector::Redirector};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, trace};

pub struct Client<'a> {
    config: &'a config::ClientConfig,
    transport: stnet::Transport,
    to_server: HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>,
    from_internal: HashMap<SocketAddr, mpsc::Receiver<stnet::RedirectorFrame>>,

    handlers: JoinSet<SocketAddr>,
}

impl<'a> Client<'a> {
    pub fn new(config: &'a config::ClientConfig, stream: tnet::TcpStream) -> Client<'a> {
        stnet::set_keepalive(&stream, true)
            .expect("keepalive should have be enabled on stream, but operation failed");
        Client {
            config,
            transport: stnet::Transport::new(stream),
            to_server: HashMap::new(),
            from_internal: HashMap::new(),
            handlers: JoinSet::new(),
        }
    }

    async fn push_tunnel_config(&mut self) -> std::result::Result<(), stnet::Error> {
        self.transport
            .write_frame(Frame::Auth(self.config.psk.clone().into()))
            .await?;

        let frame = self.transport.read_frame().await?;
        let stnet::Frame::Auth(_) = frame else {
            return Err(stnet::Error::ConnectionRefused);
        };

        let tunnels = self
            .config
            .tunnels
            .iter()
            .map(|tunnel| tunnel.remote_port)
            .collect();
        self.transport.write_frame(Frame::Tunnels(tunnels)).await?;

        let frame = self.transport.read_frame().await?;
        let stnet::Frame::Tunnels(_) = frame else {
            return Err(stnet::Error::ConnectionRefused);
        };
        info!("Pushed tunnel config to remote");
        Ok(())
    }

    pub async fn run(&mut self) -> std::result::Result<(), stnet::Error> {
        self.push_tunnel_config().await?;
        loop {
            let mut from_internal_futures: FuturesUnordered<_> = self
                .from_internal
                .iter_mut()
                .map(|(_, from_internal)| from_internal.recv())
                .collect();
            tokio::select! {
                // A tunnel has completed it's redirection
                maybe_join = self.handlers.join_next() => {
                    drop(from_internal_futures); // TODO really?
                    let addr = match maybe_join {
                        None => continue,
                        Some(Err(_)) => unreachable!(), // TODO
                        Some(Ok(h)) => h,
                    };
                    info!(addr = ?addr, "Cleaned up redirector");
                    self.to_server.remove(&addr);
                    self.from_internal.remove(&addr);
                }

                // Client receives a frame from Server
                maybe_frame = self.transport.read_frame() => {
                    drop(from_internal_futures); // TODO really?
                    let frame = match maybe_frame {
                        Err(e) => {
                            error!(cause = ?e, "failed to read");
                            return Err(e);
                        }
                        Ok(s) => s,
                    };

                    match frame {
                        Frame::Kthxbai => {
                            return Ok(());
                        }
                        Frame::Redirector(r) => {
                            if let Err(e) = self.try_datagram(r).await {
                                error!(cause = ?e, "redirector failed");
                            }
                        }
                        _ => unreachable!(),
                    }
                }

                // We have some data to send from a tunnel to the client
                maybe_recv = from_internal_futures.next() => {
                    let data = match maybe_recv {
                        None => continue,
                        Some(None) => continue,
                        Some(Some(d)) => d,
                    };

                    self.transport.write_frame(data.into()).await?;
                }
            }
        }
    }

    async fn new_conn(&mut self, d: &stnet::Datagram) -> std::result::Result<(), stnet::Error> {
        let (to_internal, from_internal) = mpsc::channel(16);
        let (to_server, from_server) = mpsc::channel(16);
        self.to_server.insert(d.id, to_server);
        self.from_internal.insert(d.id, from_internal);

        let local_port = match self.config.local_port(d.port) {
            None => return Err(format!("unknown port {}", d.port).into()),
            Some(p) => p,
        };
        let internal_addr: SocketAddr = format!("127.0.0.1:{}", local_port).parse().unwrap();
        info!(internal_addr = ?internal_addr, for_ = ?d.id, "connecting to Internal");
        let internal_stream = match tnet::TcpStream::connect(internal_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(cause = ?e, addr = ?internal_addr, for_ = ?d.id, "Failed to connect to Internal");
                return Err(e.into());
            }
        };

        let id = d.id;
        let port = d.port;
        self.handlers.spawn(async move {
            trace!(addr = ?internal_addr, "Tunnel start");
            let mut h = Redirector::new(id, port, internal_stream, to_internal, from_server);
            if let Err(e) = h.run().await {
                error!(cause = ?e, addr = ?internal_addr, "tunnel experienced error");
            }
            trace!(addr = ?internal_addr, "Tunnel done");
            id
        });
        Ok(())
    }

    async fn try_datagram(&mut self, frame: stnet::RedirectorFrame) -> std::result::Result<(), stnet::Error> {
        match frame {
            stnet::RedirectorFrame::KillListener(id) => {
                let to_server = match self.to_server.get(&id) {
                    None => {
                        error!(id = ?id,"no channel");
                        return Ok(());
                    }
                    Some(s) => s
                };
                to_server.send(frame).await?;
            },
            stnet::RedirectorFrame::Datagram(ref d) => {
                // Open a tunnel to the internal if needed
                if !self.to_server.contains_key(&d.id) {
                    if let Err(e) = self.new_conn(d).await {
                        // make sure the Server kills off the connection on its side
                        let d = stnet::RedirectorFrame::KillListener(d.id);
                        self.transport.write_frame(d.into()).await?;
                        return Err(e);
                    }
                }
                let to_server = self.to_server.get(&d.id).unwrap();
                to_server.send(frame).await?;

            },
        }

        Ok(())
    }
}
