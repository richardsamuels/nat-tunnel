use crate::{config::client as config, net as stnet, net::Frame, redirector::Redirector};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

pub struct Client<'a, T> {
    config: &'a config::ClientConfig,
    transport: stnet::Transport<T>,

    to_server: mpsc::Sender<stnet::RedirectorFrame>,
    from_internal: mpsc::Receiver<stnet::RedirectorFrame>,

    to_internal: HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>,

    handlers: JoinSet<SocketAddr>,
}

impl<'a, T> Client<'a, T>
where
    T: tokio::io::AsyncReadExt
        + tokio::io::AsyncWriteExt
        + std::marker::Unpin
        + stnet::PeerAddr
        + std::os::fd::AsRawFd,
{
    pub fn new(config: &'a config::ClientConfig, stream: T) -> Client<'a, T> {
        stnet::set_keepalive(&stream, true)
            .expect("keepalive should have be enabled on stream, but operation failed");

        let (tx, rx) = mpsc::channel(16);
        Client {
            config,
            transport: stnet::Transport::new(stream),
            handlers: JoinSet::new(),
            to_server: tx,
            from_internal: rx,
            to_internal: HashMap::new(),
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
            tokio::select! {
                // A tunnel has completed it's redirection
                maybe_join = self.handlers.join_next() => {
                    let addr = match maybe_join {
                        None => continue,
                        Some(Err(_)) => unreachable!(), // TODO
                        Some(Ok(h)) => h,
                    };
                    info!(addr = ?addr, "Cleaned up redirector");
                }

                // Client receives a frame from Server
                maybe_frame = self.transport.read_frame() => {
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
                maybe_recv = self.from_internal.recv() => {
                    let data = match maybe_recv {
                        None => continue,
                        Some(d) => d,
                    };
                    self.transport.write_frame(data.into()).await?;
                }
            }
        }
    }

    async fn new_conn(&mut self, d: &stnet::Datagram) -> std::result::Result<(), stnet::Error> {
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
        let to_server = self.to_server.clone();
        let (to_internal, from_internal) = mpsc::channel(16);
        self.to_internal.insert(d.id, to_internal);
        self.handlers.spawn(async move {
            let mut r =
                Redirector::with_stream(id, port, internal_stream, to_server, from_internal);
            let _ = r.run().await;
            id
        });
        Ok(())
    }

    async fn try_datagram(
        &mut self,
        frame: stnet::RedirectorFrame,
    ) -> std::result::Result<(), stnet::Error> {
        if let stnet::RedirectorFrame::Datagram(ref d) = frame {
            // Open a tunnel to the internal if needed
            if !self.to_internal.contains_key(&d.id) {
                if let Err(e) = self.new_conn(d).await {
                    // make sure the Server kills off the connection on its side
                    let d = stnet::RedirectorFrame::KillListener(d.id);
                    self.transport.write_frame(d.into()).await?;
                    return Err(e);
                }
            }
        }

        let to_internal = match self.to_internal.get(frame.id()) {
            None => {
                error!(id = ?frame.id(),"no channel");
                return Ok(());
            }
            Some(s) => s,
        };
        to_internal.send(frame).await?;

        Ok(())
    }
}
