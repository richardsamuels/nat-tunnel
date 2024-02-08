use tracing::{info, error};
use std::str;
use std::io::{Write, Read};
//use crate::{config, Result, Error};
use simple_tunnel::{config, net, Result, Error};
use std::process::ExitCode;
use mio::net as mnet;
use mio::{Events, Poll, Interest, Token};
use std::net::SocketAddr;
use std::io::{BufRead, BufWriter};
use simple_tunnel::redirector;
use std::sync::mpsc;

struct Client {
    poll: mio::Poll,
    events: mio::Events,

    transport: net::NetBuf,
}

impl Client {
    fn new(stream: mnet::TcpStream) -> Result<Client> {
        net::set_keepalive(&stream, true)?;
        let poll = Poll::new()?;

        let mut c = Client {
            poll,
            events: Events::with_capacity(128),
            transport: net::NetBuf::new(stream)
        };
        c.poll.registry().register(&mut c.transport, Token(0), Interest::READABLE | Interest::WRITABLE)?;
        Ok(c)
    }

    fn push_tunnel_config(&mut self, c: &config::ClientConfig) -> Result<()> {
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
                        Ok(_) => ()
                    };

                    let auth = net::Auth::new(c.psk.clone());
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

    fn run(&mut self, c: &config::ClientConfig, rx: &mpsc::Receiver<()>) -> Result<()> {
        use std::io::ErrorKind;
        use rmp_serde::decode::Error as DeError;

        loop {
            self.poll.poll(&mut self.events, None)?;

            for ev in &self.events {
                if let Ok(_) = rx.try_recv() {
                    return Ok(());
                }
                if ev.token() == Token(0) && ev.is_readable() {
                    loop {
                        let pd: simple_tunnel::net::PlzDial = match self.transport.read() {
                            Ok(pd) => pd,
                            Err(net::Error::WouldBlock) => break,
                            Err(_e) => return Err("connection dead".into()),
                        };

                        let from_addr: SocketAddr = format!("{}:{}", &c.addr, &pd.via_port).parse().unwrap();
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
                        let to_addr: SocketAddr = format!("127.0.0.1:{}", local_port).parse().unwrap();
                        info!(dial = ?pd, local_port = local_port, from = ?from_addr, to = ?to_addr, "Received dial request");
                        let from_stream = match std::net::TcpStream::connect(from_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!(cause = ?e, from = ?from_addr, "Failed to connect to remote");
                                continue
                            }
                        };
                        let to_stream = match std::net::TcpStream::connect(to_addr) {
                            Ok(s) => s,
                            Err(e) => {
                                error!(cause = ?e, to = ?to_addr, "Failed to connect to b");
                                continue
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
        let bai = simple_tunnel::net::Kthxbai{};
        let _ = self.transport.write(&bai);
        info!("Closing connection to remote");
    }
}


fn main2() -> Result<()> {
    let (sigint_tx, sigint_rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = sigint_tx.send(());
    })?;

    let c = config::load_client_config();

    loop {
        let addr: SocketAddr = format!("{}:{}", c.addr, c.port).parse().unwrap();
        info!("Handshaking with {}", &addr);
        let stream = mnet::TcpStream::connect(addr)?;
        let mut client = Client::new(stream)?;

        match client.push_tunnel_config(&c) {
            Err(e) => panic!("connection to {} failed: {}", addr, e),
            Ok(_) => ()
        };

        match client.run(&c, &sigint_rx) {
            Ok(_) => return Ok(()),
            Err(e) => {
                let s = e.to_string();
                if s == "Interrupted system call (os error 4)" {
                    return Ok(());
                } else if s == "connection dead" {
                    info!("Connection to remote appears dead. Retrying");
                    continue;
                }
                error!(cause = ?e, "client error");
            }
        }
    }
}



fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    ExitCode::from(match main2() {
        Ok(_) => 0,
        Err(e) => {
            error!(cause=e, "Exiting");
            1
        }
    })
}
