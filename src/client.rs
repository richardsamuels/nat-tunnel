use crate::{
    config::client as config, net as stnet, net::Frame, net::RedirectorFrame, redirector, Result,
};
use futures::stream::TryStreamExt;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug_span, error, info, trace};

pub struct Client<T> {
    config: config::Config,
    token: CancellationToken,
    peer_addr: SocketAddr,
    // Frames to send to the server
    to_server: mpsc::Sender<stnet::RedirectorFrame>,
    // Frames being received from to
    from_internal: mpsc::Receiver<stnet::RedirectorFrame>,

    to_internal: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>>>,

    // net == internal
    chan2net_handlers: JoinSet<SocketAddr>,
    net2chan_handlers: JoinSet<SocketAddr>,
    phantom: std::marker::PhantomData<T>,
}

impl<T> Client<T>
where
    T: tokio::io::AsyncReadExt
        + tokio::io::AsyncWriteExt
        + std::marker::Unpin
        + std::os::fd::AsRawFd
        + futures::Stream
        + futures::Sink<stnet::Frame>,
{
    pub fn new(config: config::Config, token: CancellationToken, stream: &T) -> Client<T> {
        let (tx, rx) = mpsc::channel(16);

        let peer_addr = stream.peer_addr();

        let to_internal = HashMap::new().into();

        Client {
            config,
            token,
            peer_addr,
            chan2net_handlers: JoinSet::new(),
            net2chan_handlers: JoinSet::new(),
            to_server: tx,
            from_internal: rx,
            to_internal,
            phantom: std::marker::PhantomData,
        }
    }

    pub async fn run(&mut self, stream: T) -> Result<()> {
        // tokio spawn the handlers
        //
        //
        let (sc, from_server_lm) = ServerComm::with_stream(
            self.config.clone(),
            self.token.clone(),
            self.from_internal,
            self.to_internal.clone(),
            stream,
        )?;
        sc.push_tunnel_config().await?;

        let (c2s, s2c) = sc.split();

        tokio::spawn(async move { c2s.run().await });
        tokio::spawn(async move { s2c.run().await });

        let span = debug_span!("loop", addr = ?self.peer_addr);
        let _guard = span.enter();
        let ret = loop {
            tokio::select! {
                // A tunnel has completed it's redirection
                maybe_join = self.chan2net_handlers.join_next() => {
                    let addr = match maybe_join {
                        None => continue,
                        Some(Err(e)) => {
                            error!(cause = ?e, "chan2net redirector task panicked");
                            continue
                        },
                        Some(Ok(h)) => h,
                    };
                    trace!(addr = ?addr, "chan2net redirector cleaned up");
                }
                maybe_join_net2chan = self.net2chan_handlers.join_next() => {
                    let addr = match maybe_join_net2chan {
                        None => continue,
                        Some(Err(e)) => {
                            error!(cause = ?e, "net2chan redirector task panicked");
                            continue
                        },
                        Some(Ok(h)) => h,
                    };
                    trace!(addr = ?addr, "net2chan redirector cleaned up");
                }

                maybe_listener_frame = from_server_lm.recv() => {
                    match maybe_listener_frame{
                        None => continue,
                        Some(Frame::Kthxbai) => {
                            info!("server sent shutdown notification");
                            break Ok(())
                        },
                        Some(Frame::Redirector(r)) => {
                            self.redirector_frame(r).await?
                        }
                        Some(f) => {
                            error!(frame = ?f, addr = ?self.peer_addr, "received unexpected frame");
                        }

                    }

                }

                _ = self.token.cancelled() => {
                    break Ok(());
                }
            }
        };
        ret
    }

    async fn new_conn(&mut self, id: SocketAddr, port: u16) -> Result<()> {
        let tunnel_cfg = match self.config.tunnel(port) {
            None => {
                unreachable!();
            }
            Some(p) => p,
        };
        let internal_addr: SocketAddr =
            format!("{}:{}", tunnel_cfg.local_hostname, tunnel_cfg.local_port)
                .parse()
                .unwrap();
        info!(for_ = ?id, internal_addr = ?internal_addr, "connecting to Internal");
        let internal_stream = match tnet::TcpStream::connect(internal_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(cause = ?e, addr = ?internal_addr, for_ = ?id, "Failed to connect to Internal");
                return Err(e.into());
            }
        };

        let to_server = self.to_server.clone();
        let token = self.token.clone();
        let mtu = self.config.mtu;
        let (to_internal, from_internal) = mpsc::channel(16);

        {
            let mut toi = self.to_internal.lock().unwrap();
            toi.insert(id, to_internal);
        };

        let (mut r, mut w) = redirector::with_stream(
            id,
            port,
            mtu,
            token,
            from_internal,
            to_server,
            internal_stream,
        );
        self.chan2net_handlers.spawn(async move {
            w.run().await;
            id
        });
        self.net2chan_handlers.spawn(async move {
            r.run().await;
            id
        });
        Ok(())
    }

    async fn redirector_frame(&mut self, frame: stnet::RedirectorFrame) -> Result<()> {
        match frame {
            stnet::RedirectorFrame::StartListener(id, port) => {
                // Open a tunnel to the internal if needed
                let has_key = { self.to_internal.lock().unwrap().contains_key(&id) };
                if !has_key {
                    if let Err(e) = self.new_conn(id, port).await {
                        // make sure the Server kills off the connection on its side
                        let d = stnet::RedirectorFrame::KillListener(id);
                        self.to_server.send(d.into()).await?;
                        return Err(e);
                    }
                }
            }
            stnet::RedirectorFrame::KillListener(ref id) => {
                let mut toi = self.to_internal.lock().unwrap();
                toi.remove(id);
            }
            _ => {
                error!(frame = ?frame, addr = ?self.peer_addr, "received unexpected frame");
            }
        }

        Ok(())
    }
}

struct ServerComm<W, R> {
    c2s: Client2Server<W>,
    s2c: Server2Client<R>,
    config: config::Config,
}

impl<W, R> ServerComm<W, R>
where
    R: tokio::io::AsyncReadExt + std::marker::Unpin + futures::StreamExt,
    W: tokio::io::AsyncWriteExt + std::marker::Unpin + futures::SinkExt<stnet::Frame>,
{
    pub async fn push_tunnel_config(&mut self) -> stnet::Result<()> {
        self.c2s
            .write_frame(Frame::Auth(self.config.psk.clone().into()))
            .await?;

        let frame = self.s2c.read_frame().await?;
        let stnet::Frame::Auth(_) = frame else {
            return Err(stnet::Error::ConnectionRefused.into());
        };

        let tunnels = self
            .config
            .tunnels
            .iter()
            .map(|tunnel| tunnel.remote_port)
            .collect();
        self.c2s.write_frame(Frame::Tunnels(tunnels)).await?;

        let frame = self.s2c.read_frame().await?;
        let stnet::Frame::Tunnels(_) = frame else {
            return Err(stnet::Error::ConnectionRefused.into());
        };
        trace!("Pushed tunnel config to remote");
        Ok(())
    }

    fn with_stream<T>(
        config: config::Config,
        token: CancellationToken,
        from_internal: mpsc::Receiver<stnet::RedirectorFrame>,
        to_internal: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>>>,
        stream: T,
    ) -> Result<(Self, mpsc::Receiver<stnet::Frame>)>
    where
        T: tokio::io::AsyncReadExt
            + tokio::io::AsyncWriteExt
            + std::marker::Unpin
            + std::os::fd::AsRawFd
            + futures::Stream
            + futures::Sink<stnet::Frame>,
    {
        let peer_addr = stream.peer_addr();
        stnet::set_keepalive(&stream, true)
            .expect("keepalive should be enabled on stream, but operation failed");

        let (writer, reader) = stnet::frame(stream).split();
        let (to_connman, from_server_lm) = mpsc::channel(16);
        let mut c2s =
            Client2Server::with_sink(peer_addr.clone(), token.clone(), from_internal, writer);
        let mut s2c =
            Server2Client::with_stream(peer_addr, token.clone(), to_internal, to_connman, reader);
        let mut out = ServerComm { config, c2s, s2c };
        Ok((out, from_server_lm))
    }

    fn split(self) -> (Client2Server<W>, Server2Client<R>) {
        (self.c2s, self.s2c)
    }
}

struct Server2Client<R> {
    peer_addr: SocketAddr,
    token: CancellationToken,
    to_internal: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>>>,
    to_connman: mpsc::Sender<stnet::Frame>,
    framed: SplitStream<stnet::Framed<R>>,
}

impl<R> Server2Client<R>
where
    R: tokio::io::AsyncReadExt + std::marker::Unpin + futures::StreamExt,
{
    fn with_stream(
        peer_addr: SocketAddr,
        token: CancellationToken,
        to_internal: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>>>,
        to_connman: mpsc::Sender<stnet::Frame>,
        stream: SplitStream<stnet::Framed<R>>,
    ) -> Self {
        Server2Client {
            peer_addr,
            framed: stream,
            token,
            to_internal,
            to_connman,
        }
    }

    pub async fn read_frame(&mut self) -> stnet::Result<Frame> {
        use crate::net::error::*;
        use crate::net::reconnectable_err;

        let try_read =
            match tokio::time::timeout(std::time::Duration::from_secs(5), self.framed.try_next())
                .await
            {
                Ok(x) => x,
                Err(_) => {
                    error!("Write operation timed out");
                    return Err(stnet::Error::ConnectionDead.into());
                }
            };

        match try_read {
            Err(e) if reconnectable_err(&e) => {
                return Err(Error::ConnectionDead);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(Error::ConnectionDead);
                }
                Err(stnet::Error::Io {
                    message: "failed to read frame".to_string(),
                    source: e,
                    backtrace: snafu::Backtrace::capture(),
                })
            }
            Ok(None) => Err(Error::ConnectionDead),
            Ok(Some(frame)) => Ok(frame),
        }
    }

    pub async fn run(&mut self) -> stnet::Result<()> {
        let t = self.token.clone();
        let ret = loop {
            tokio::select! {
                maybe_frame = self.read_frame() => {
                    let frame = match maybe_frame {
                        Err(e) => {
                            error!(cause = ?e, "failed to read");
                            break Err(e.into());
                        }
                        Ok(s) => s,
                    };

                    match frame {
                        Frame::Kthxbai => {
                            if let Err(e) = self.to_connman.send(frame).await {
                                error!(cause = ?e, "failed to send frame to connection manager");
                            }
                            break Ok(());
                        }
                        Frame::Redirector(RedirectorFrame::StartListener(_, _)) | Frame::Redirector(RedirectorFrame::KillListener(_)) => {
                            if let Err(e) = self.to_connman.send(frame).await {
                                error!(cause = ?e, "failed to send frame to connection manager");
                            }
                        }
                        Frame::Redirector(r) => {
                            let toi = self.to_internal.lock().unwrap();
                            match toi.get(&r.id()) {
                                None => {
                                    error!(id = ?r.id(), "no channel");
                                    return Ok(());
                                }
                                Some(s) => {
                                    if let Err(e) = s.send(r).await {
                                        error!(cause = ?e, "failed to send frame");
                                        // TODO wrong
                                        return Ok(())
                                    }
                                }
                            };
                        }
                        f => {
                            error!(frame = ?f, addr = ?self.peer_addr, "received unexpected frame");
                        }
                    }
                }

                _ = t.cancelled() => {
                    break Ok(());
                }
            }
        };
        ret
    }
}

struct Client2Server<W> {
    peer_addr: SocketAddr,
    token: CancellationToken,
    from_internal: mpsc::Receiver<stnet::RedirectorFrame>,
    framed: SplitSink<stnet::Framed<W>, stnet::Frame>,
}

impl<W> Client2Server<W>
where
    W: tokio::io::AsyncWriteExt + std::marker::Unpin + futures::SinkExt<stnet::Frame>,
{
    fn with_sink(
        peer_addr: SocketAddr,
        token: CancellationToken,
        from_internal: mpsc::Receiver<stnet::RedirectorFrame>,
        sink: SplitSink<stnet::Framed<W>, stnet::Frame>,
    ) -> Self {
        Client2Server {
            framed: sink,
            peer_addr,
            token,
            from_internal,
        }
    }

    async fn run(&mut self) -> stnet::Result<()> {
        let ret = loop {
            tokio::select! {
                maybe_recv = self.from_internal.recv() => {
                    let data = match maybe_recv {
                        None => continue,
                        Some(d) => d,
                    };
                    if let Err(e) = self.write_frame(data.into()).await {
                        error!(cause = ?e, "failed to write frame");
                        break Err(e.into());
                    };
                }

                _ = self.token.cancelled() => {
                    break Ok(());
                }
            }
        };

        ret
    }

    async fn write_frame(&mut self, t: Frame) -> stnet::Result<()> {
        use crate::net::error::*;
        use crate::net::reconnectable_err;

        match tokio::time::timeout(std::time::Duration::from_secs(5), self.framed.send(t)).await {
            Ok(Ok(_)) => (),
            Ok(Err(e)) if reconnectable_err(&e) => {
                return Err(Error::ConnectionDead);
            }
            Ok(Err(e)) => {
                return Err(stnet::Error::Io {
                    message: "failed to write frame".to_string(),
                    source: e.into(),
                    backtrace: snafu::Backtrace::capture(),
                })
            }
            Err(_) => {
                error!("Write operation timed out");
                return Err(stnet::Error::ConnectionDead.into());
            }
        }

        // XXX Flush MUST be called here. See tokio_rustls docs:
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/index.html#why-do-i-need-to-call-poll_flush
        self.framed.flush().await.map_err(|e| stnet::Error::Io {
            message: "failed to flush".to_string(),
            source: e.into(),
            backtrace: snafu::Backtrace::capture(),
        })
    }
}
