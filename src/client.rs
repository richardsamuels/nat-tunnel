use mio::net as mnet;
use mio::{Events, Interest, Poll, Token};
use crate::redirector;
use crate::{config, net as stnet, Result};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::io::Write;
use tracing::{error, info};

pub struct Client {
    poll: mio::Poll,
    events: mio::Events,

    transport: stnet::NetBuf,
}

impl Client {
    pub fn new(stream: mnet::TcpStream) -> Result<Client> {
        stnet::set_keepalive(&stream, true)?;
        let poll = Poll::new()?;

        let mut c = Client {
            poll,
            events: Events::with_capacity(128),
            transport: stnet::NetBuf::new(stream),
        };
        c.poll.registry().register(
            &mut c.transport,
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(c)
    }

    pub fn push_tunnel_config(&mut self, c: &config::ClientConfig) -> Result<()> {
        'outer: loop {
            self.poll.poll(&mut self.events, None)?;

            for ev in &self.events {
                if ev.token() == Token(0) && ev.is_writable() {
                    match self.transport.stream().peer_addr() {
                        Err(err)
                            if err.kind() == std::io::ErrorKind::NotConnected
                                || err.raw_os_error() == Some(libc::EINPROGRESS) =>
                        {
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                        Ok(_) => (),
                    };

                    let auth = stnet::Auth::new(c.psk.clone());
                    self.transport.write(&auth)?;
                    self.transport.flush()?;

                    self.transport.write(&c)?;
                    self.transport.flush()?;
                    info!("Pushed tunnel config to remote");
                    break 'outer;
                }
            }
        }

        self.events.clear();
        Ok(())
    }

    pub fn run(&mut self, c: &config::ClientConfig, rx: &mpsc::Receiver<()>) -> Result<()> {
        loop {
            self.poll.poll(&mut self.events, None)?;

            for ev in &self.events {
                if rx.try_recv().is_ok() {
                    return Ok(());
                }
                if ev.token() == Token(0) && ev.is_readable() {
                    loop {
                        let pd: stnet::PlzDial = match self.transport.read() {
                            Ok(pd) => pd,
                            Err(stnet::Error::WouldBlock) => break,
                            Err(_e) => return Err("connection dead".into()),
                        };

                        let from_addr: SocketAddr =
                            format!("{}:{}", &c.addr, &pd.via_port).parse().unwrap();
                        let local_port: u16 = {
                            let mut out = 0;
                            for t in &c.tunnels {
                                if t.remote_port == pd.remote_port {
                                    out = t.local_port;
                                    break;
                                }
                            }
                            out
                        };
                        let to_addr: SocketAddr =
                            format!("127.0.0.1:{}", local_port).parse().unwrap();
                        info!(dial = ?pd, local_port = local_port, from = ?from_addr, to = ?to_addr, "Received dial request");
                        let from_stream = match std::net::TcpStream::connect(from_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!(cause = ?e, from = ?from_addr, "Failed to connect to remote");
                                continue;
                            }
                        };
                        let to_stream = match std::net::TcpStream::connect(to_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!(cause = ?e, to = ?to_addr, "Failed to connect to b");
                                continue;
                            }
                        };
                        from_stream.set_nonblocking(true)?;
                        let from_stream = mnet::TcpStream::from_std(from_stream);
                        to_stream.set_nonblocking(true)?;
                        let to_stream = mnet::TcpStream::from_std(to_stream);

                        // TODO auth
                        //let mut transport = net::NetBuf::new(from_stream);
                        //let auth: net::Auth = net::Auth::new(c.psk.clone());
                        //transport.write(&auth)?;
                        //transport.flush()?;
                        //std::thread::spawn(|| redirector::redirector(transport.eject(), to_stream));
                        std::thread::spawn(|| redirector::redirector(from_stream, to_stream));
                    }
                }
            }
        }
    }
}

impl std::ops::Drop for Client {
    fn drop(&mut self) {
        let bai = stnet::Kthxbai {};
        let _ = self.transport.write(&bai);
        info!("Closing connection to remote");
    }
}
