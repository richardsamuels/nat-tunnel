use crate::tunnel::TunnelHandler;
use crate::{config, net as stnet, net::Frame, Result};
use futures::stream::FuturesUnordered;
use futures::SinkExt;
use futures::StreamExt;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

pub struct Client<'a> {
    config: &'a config::ClientConfig,
    transport: crate::net::Framed,
    to_bs: HashMap<SocketAddr, mpsc::Sender<stnet::Datagram>>,
    from_bs: HashMap<SocketAddr, mpsc::Receiver<stnet::Datagram>>,

    handlers: JoinSet<Result<SocketAddr>>,
}

impl<'a> Client<'a> {
    pub fn new(config: &config::ClientConfig, stream: tnet::TcpStream) -> Result<Client> {
        stnet::set_keepalive(&stream, true)?;
        let c = Client {
            config,
            transport: stnet::frame(stream),
            to_bs: HashMap::new(),
            from_bs: HashMap::new(),
            handlers: JoinSet::new(),
        };
        Ok(c)
    }

    pub async fn push_tunnel_config(&mut self) -> Result<()> {
        self.transport
            .send(Frame::Auth(self.config.psk.clone().into()))
            .await?;
        self.transport.flush().await?;

        let tunnels = {
            let mut out = Vec::new();
            for tunnel in &self.config.tunnels {
                out.push(tunnel.remote_port);
            }
            out
        };
        self.transport.send(Frame::Tunnels(tunnels)).await?;
        self.transport.flush().await?;
        info!("Pushed tunnel config to remote");
        Ok(())
    }

    pub async fn run(&mut self) -> std::result::Result<(), stnet::Error> {
        loop {
            let mut futures: FuturesUnordered<_> = self
                .from_bs
                .iter_mut()
                .map(|(_, from_b)| from_b.recv())
                .collect();
            tokio::select! {
                maybe_join = self.handlers.join_next() => {
                    drop(futures);
                    let h = match maybe_join {
                        None => continue,
                        Some(Err(_)) => unreachable!(),
                        Some(Ok(Ok(h))) => h,
                        Some(Ok(Err(_))) => unreachable!(),
                    };
                    self.to_bs.remove(&h);
                    self.from_bs.remove(&h);
                }
                maybe_read = self.transport.try_next() => {
                    drop(futures); // TODO really?
                    let maybe_frame = match maybe_read {
                        Err(e) => {
                            error!(cause = ?e, "failed to read");
                            return Err(e.into());
                        }
                        Ok(s) => s,
                    };
                    let frame: Frame = match maybe_frame {
                        None => return Err(stnet::Error::ConnectionDead),
                        Some(f) => f,
                    };

                    match frame {
                        Frame::Kthxbai => return Ok(()),
                        Frame::Datagram(d) => {
                            match self.datagram(d).await {
                                e @ Err(stnet::Error::ConnectionDead) => break e,
                                Err(e) => {
                                    error!(cause = ?e, "failed to handle datagram");
                                }
                                Ok(_) => (),
                            };
                        }
                        _ => unreachable!(),
                    }

                }
                maybe_recv = futures.next() => {
                    let data = match maybe_recv {
                        None => continue,
                        Some(None) => continue,
                        Some(Some(f)) => f,
                    };

                    if let Err(e) = self.transport.send(data.into()).await {
                        return Err(e.into());
                    };
                }
            }
        }
    }

    async fn new_conn(&mut self, d: &stnet::Datagram) -> std::result::Result<(), stnet::Error> {
        let local_port = match self.config.local_port(d.port) {
            None => return Err(format!("unknown port {}", d.port).into()),
            Some(p) => p,
        };
        let b_addr: SocketAddr = format!("127.0.0.1:{}", local_port).parse().unwrap();
        info!(b_addr = ?b_addr, "connecting to `b`");
        let b_stream = match tnet::TcpStream::connect(b_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(cause = ?e, b = ?b_addr, "Failed to connect to `b`");
                return Err(e.into());
            }
        };

        let (to_b, from_b) = mpsc::channel(16);
        let (to_client, from_client) = mpsc::channel(16);
        self.to_bs.insert(d.id, to_client);
        self.from_bs.insert(d.id, from_b);

        let id = d.id;
        let port = d.port;
        self.handlers.spawn(async move {
            let mut h = TunnelHandler::new(id, port, b_stream, to_b, from_client);
            if let Err(e) = h.run().await {
                error!(cause = ?e, addr = ?b_addr, "tunnel experienced error");
            }
            info!(addr = ?b_addr, "Tunnel done");
            Ok(id)
        });
        Ok(())
    }
    async fn datagram(&mut self, d: stnet::Datagram) -> std::result::Result<(), stnet::Error> {
        if !self.to_bs.contains_key(&d.id) {
            self.new_conn(&d).await?;
        }
        let to_client = self.to_bs.get(&d.id).unwrap();
        let _ = to_client.send(d).await;
        Ok(())
    }
}
