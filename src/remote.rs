use std::net;
use crate::net::{NetBuf, PlzDial};
use crate::net as stnet;
use crate::config;
use crate::Result;
use tracing::{error, info, trace};
use serde::{Deserialize, Serialize};
use mio::net as mnet;
use mio::{Events, Poll, Interest, Token, Registry};
use std::vec::Vec;
use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Receiver;
use std::io::{Write, ErrorKind};
use std::time::{Instant, Duration};
use std::ops::Deref;

fn redirector(psk: String, a_stream: mnet::TcpStream, listener: std::net::TcpListener, tx: oneshot::Sender<PlzDial>) -> Result<()> {
    use std::time::{Instant, Duration};
    use std::io::ErrorKind;

    let remote_addr = a_stream.local_addr()?;
    let port = listener.local_addr()?.port();
    info!("Redirector ready on port {}", &port);
    let pd = PlzDial {
        remote_port: remote_addr.port(),
        via_port: port
    };
    tx.send(pd)?;

    let now = Instant::now();
    let wait = Duration::new(5,0);
    'outer: loop {
        let (client_stream, client_addr) = match listener.accept() {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                if now.elapsed() >= wait {
                    error!(port = port, "Timeout on redirect listener");
                    break;
                }
                continue;
            }
            Err(e) => {
                if now.elapsed() >= wait {
                    error!(port = port, "Timeout on redirect listener");
                    break;
                }
                error!(cause = ?e, port = port, "Failed to accept redirector listener");
                continue;
            }
            Ok(a) => a
        };
        client_stream.set_nonblocking(true)?;
        let mut client_stream = mnet::TcpStream::from_std(client_stream);
        let mut transport = stnet::NetBuf::new(client_stream);
        // TODO auth
        //let auth: stnet::Auth = transport.read()?;

        //// TODO constant time compare
        //if auth.psk.deref() != &psk {
        //    error!(port = port, addr = ?client_addr, "Wrong PSK supplied to redirector");
        //}

        crate::redirector::redirector(a_stream, transport.eject())?;
        //crate::redirector::redirector(a_stream, client_stream)?;

        break 'outer;
    }
    info!(port=port, "Closing redirector");

    Ok(())
}

struct Mio {
    poll: Poll,
    events: Events,
}

struct Net {
    listener: mnet::TcpListener,

    clients: HashMap<SocketAddr, NetBuf>,
    tunnel_port_2_client: HashMap<u16, SocketAddr>,
    // listeners for tunnels
    remote_ports: HashMap<u16, mnet::TcpListener>,

    tokens: stnet::Tokens<SocketAddr>,
}
impl Net {
    fn get_addr(&self, v:usize) -> Option<&SocketAddr> {
        self.tokens.get(v)
    }
    fn get_by(&mut self, v: usize) -> Option<&mut NetBuf> {
        let addr = self.tokens.get(v)?.clone();
        self.get_by_addr(&addr)
    }
    fn get_by_addr(&mut self, addr: &SocketAddr) -> Option<&mut NetBuf> {
        self.clients.get_mut(&addr)
    }

    fn remove_client_by_addr(&mut self, addr: &SocketAddr) {
        self.clients.remove(&addr);
        // TODO scans the whole hashmap.
        let rp_cleanup: Vec<u16> = self.tunnel_port_2_client.iter().filter(|(_, a)| &addr == a).map(|(port, _)| port.clone()).collect();
        for port in rp_cleanup {
            info!("Cleanup port {}", port);
            self.tunnel_port_2_client.remove(&port);
            self.remote_ports.remove(&port);
        }
    }

    pub fn insert_client(&mut self, addr: SocketAddr, transport: NetBuf) {
        self.clients.insert(addr, transport);
    }

    pub fn insert_token(&mut self, addr: &SocketAddr) -> Option<usize> {
        self.tokens.insert(addr.clone())
    }

    pub fn insert_tunnel(&mut self, port: u16, addr: SocketAddr, listener: mnet::TcpListener) {
        self.remote_ports.insert(port, listener);
        self.tunnel_port_2_client.insert(port, addr);
    }

    pub fn get_client_transport(&mut self, port: u16) -> Option<&mut NetBuf> {
        let i = self.tunnel_port_2_client.get(&port)?;
        self.clients.get_mut(i)
    }
    pub fn get_tunnel_listener(&mut self, port: u16) -> Option<&mut mnet::TcpListener> {
        self.remote_ports.get_mut(&port)
    }

    pub fn has_tunnel(&self, port: u16) -> bool {
        self.tunnel_port_2_client.contains_key(&port)
    }

    pub fn cleanup_stale_clients(&mut self) -> Result<()> {
        use std::io::ErrorKind;

        let mut buf = [0u8; 1];
        let cleanup: HashSet<SocketAddr> = self.clients.iter_mut().filter(|(_, &mut ref c)| {
            match c.peek(&mut buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => false,
                // exclude 0 bytes read b/c it indicates closed network sockets
                Ok(n) if n > 0 => false,
                _ => true
            }
        }).map(|x| x.0.clone()).collect();
        trace!(clients = ?cleanup, "Cleaning up dead clients");
        if cleanup.len() > 0 {
            info!("Cleaning up dead clients");
        }
        for addr in &cleanup {
            self.remove_client_by_addr(&addr);
        }

        Ok(())
    }

    pub fn accept(&mut self, psk: &String, registry: &Registry) -> stnet::Result<()> {
        let (socket, addr) = match self.listener.accept() {
            Err(e) => return Err(e.into()),
            Ok(l) => l
        };
        let mut transport = stnet::NetBuf::new(socket);
        let auth: stnet::Auth = transport.read()?;
        if psk != auth.psk.deref() { // TODO: constant time compare
            error!("Incorrect PSK from {}", addr);
            return Err(format!("Incorrect PSK from {}", addr).into());
        }
        info!("Accepted client {}", addr);
        let cc: config::ClientConfig = transport.read()?;

        for tunnel in &cc.tunnels {
            if self.has_tunnel(tunnel.remote_port) {
                return Err(format!("duplicate port {}", &tunnel.remote_port).into());
            }
        }

        let k = self.insert_token(&addr).unwrap();
        registry.register(&mut transport, Token(k), Interest::READABLE)?;
        self.insert_client(addr.clone(), transport);

        for tunnel in cc.tunnels {
            let bind_addr: SocketAddr = format!("0.0.0.0:{}", &tunnel.remote_port).parse().unwrap();
            let listener = mnet::TcpListener::bind(bind_addr)?;
            info!(port=&tunnel.remote_port, "Binding new tunnel");

            self.insert_tunnel(tunnel.remote_port, addr, listener);
            let l: &mut mnet::TcpListener = &mut self.get_tunnel_listener(tunnel.remote_port).unwrap();
            registry.register(l, Token(tunnel.remote_port as usize), Interest::READABLE)?;
        }

        Ok(())
    }

    pub fn call_me_maybe(&mut self, pd: PlzDial) -> Result<()> {
        let client: &mut NetBuf = match self.get_client_transport(pd.remote_port) {
            Some(c) => c,
            None => {
                return Err("Missing client".into());
            }
        };
        info!(dial = ?pd, client = ?client.stream().peer_addr(), "Requesting client dial redirector");
        client.write(&pd)?;
        client.flush()?;
        Ok(())
    }

}

pub struct Remote {
    net: Net,
    mio: Mio,
}

impl Remote {
    pub fn new(listener: mnet::TcpListener) -> Result<Remote> {
        let poll = Poll::new()?;
        let mut c = Remote{
            net: Net {
                listener,
                clients: HashMap::new(),
                tunnel_port_2_client: HashMap::new(),
                remote_ports: HashMap::new(),
                tokens: stnet::Tokens::with_starting_offset(65_536 + 1),
            },
            mio: Mio {
                poll: poll,
                events: Events::with_capacity(128),
            }
        };
        c.mio.poll.registry().register(&mut c.net.listener, Token(0), Interest::READABLE)?;
        Ok(c)
    }

    pub fn run(&mut self, psk: &String) -> Result<()> {
        use std::io::ErrorKind;
        use rmp_serde::decode::Error as DeError;
        use std::thread::JoinHandle;

        let mut last_check = Instant::now();
        let check_interval = Duration::new(5, 0); // TODO parameterize
        let mut handlers: Vec<JoinHandle<_>> = Vec::new(); // TODO join
        'outer: loop {
            self.mio.poll.poll(&mut self.mio.events, Some(Duration::new(1,0)))?;
            if last_check.elapsed() >= check_interval {
                let _ = self.net.cleanup_stale_clients();
                last_check = Instant::now();

                let stale_handlers: Vec<usize> = handlers.iter().enumerate().filter(|(_, &ref h)| !h.is_finished()).map(|(i, _)| i).collect();
                for i in stale_handlers.iter().rev() {
                    handlers.remove(i.clone());
                }
            }

            for ev in &self.mio.events {
                if ev.token() == Token(0) && ev.is_readable() {
                    // This is a new client
                    loop {
                        match &self.net.accept(&psk, self.mio.poll.registry()) {
                            Err(crate::net::Error::WouldBlock) => break,
                            Err(e) => {
                                error!(cause = ?e);
                                continue
                            },
                            _ => continue
                        }
                    }

                } else if ev.token().0 > 65_536 && ev.is_readable() {
                    // this is an incoming message from a client that is
                    // already authenticated
                    loop {
                        let token = ev.token();
                        if ev.is_readable() {
                            let addr = self.net.get_addr(token.0).unwrap().clone();
                            //let buf = self.net.get_by(token.0).unwrap();

                            //let _: stnet::Kthxbai = match buf.read() {
                            //    Err(stnet::Error::WouldBlock) => break,
                            //    Err(e) => {
                            //        error!(cause = ?e, "Failed to read client");
                            //        continue;
                            //    }
                            //    Ok(s) => s
                            //};

                            // Client is shutting down
                            self.net.remove_client_by_addr(&addr);
                        }
                    }

                } else if ev.token() != Token(0) && ev.is_readable() {
                    // this is an incoming connection on a remote_port
                    loop {
                        let port = ev.token().0;
                        let listener = self.net.get_tunnel_listener(port as u16).unwrap();
                        let (stream, _addr) = match listener.accept() {
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                                break
                            },
                            Err(e) => {
                                error!(cause = ?e, port = ?port, "failed to accept connection from a");
                                continue;
                            }
                            Ok(o) => o,
                        };

                        let listener = std::net::TcpListener::bind("0.0.0.0:0")?;
                        listener.set_nonblocking(true)?;
                        let (tx, rx) = oneshot::channel();
                        let psk_ = psk.clone();
                        let h = std::thread::spawn(move || {
                            let _ = redirector(psk_, stream, listener, tx);
                        });
                        handlers.push(h);

                        // yield until the thread is ready to accept a connection
                        // this should be instantaneous
                        match rx.recv() {
                            Ok(pd) => self.net.call_me_maybe(pd)?,
                            Err(e) => error!(cause = ?e, "Failed to request client dial operation"),
                        };
                    }
                }
            }
        }
        for h in handlers {
            let _ = h.join();
        }
        Ok(())
    }



}
