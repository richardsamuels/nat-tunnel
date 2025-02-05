use crate::string::LimitedString;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::vec::Vec;

#[derive(Debug, Deserialize, Serialize)]
pub enum RedirectorFrame {
    StartListener(SocketAddr, u16),
    Datagram(Datagram),
    // Indicate that no further data will come from the sender.
    // i.e. HALF CLOSED
    KillListener(SocketAddr),
}

impl RedirectorFrame {
    pub fn id(&self) -> &SocketAddr {
        match self {
            RedirectorFrame::StartListener(id, _) => id,
            RedirectorFrame::Datagram(d) => &d.id,
            RedirectorFrame::KillListener(id) => id,
        }
    }
}
impl std::convert::From<Datagram> for RedirectorFrame {
    fn from(value: Datagram) -> Self {
        RedirectorFrame::Datagram(value)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Frame {
    Auth(LimitedString<512>),
    Tunnels(Vec<u16>),
    ListenerStart(SocketAddr),
    Redirector(RedirectorFrame),
    ListenerEnd(SocketAddr),
    Kthxbai,
    Heartbeat,
}

impl std::convert::From<Datagram> for Frame {
    fn from(value: Datagram) -> Self {
        RedirectorFrame::Datagram(value).into()
    }
}

impl std::convert::From<RedirectorFrame> for Frame {
    fn from(value: RedirectorFrame) -> Self {
        Frame::Redirector(value)
    }
}

/// Represents data that is being shuffled around from Client <-> Server
#[derive(Debug, Deserialize, Serialize)]
pub struct Datagram {
    #[serde(rename = "i")]
    pub id: SocketAddr, // up to 16
    #[serde(rename = "p")]
    pub port: u16, // 16
    #[serde(rename = "d", with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// List of errors that imply the Client should try to reconnect to the Server
pub(crate) fn reconnectable_err(err: &futures::io::Error) -> bool {
    use futures::io::ErrorKind::*;

    match err.kind() {
        ConnectionReset|
        //NetworkUnreachable|
        ConnectionAborted|
        //NetworkDown|
        BrokenPipe => true,
        _ => false
    }
}

pub fn set_keepalive(stream: &std::net::TcpStream) -> std::io::Result<()> {
    use socket2::{Socket, TcpKeepalive};
    use std::os::fd::{AsRawFd, FromRawFd};

    stream.set_nodelay(true)?;
    let fd = stream.as_raw_fd();
    let dup_fd = unsafe { libc::dup(fd) };
    let socket2 = unsafe { Socket::from_raw_fd(dup_fd) };
    let keepalive = TcpKeepalive::new().with_time(std::time::Duration::from_secs(10));
    socket2.set_tcp_keepalive(&keepalive)?;
    set_tcp_user_timeout(&socket2)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn set_tcp_user_timeout(_socket2: &socket2::Socket) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn set_tcp_user_timeout(socket2: &socket2::Socket) -> std::io::Result<()> {
    // TODO USER_TIMEOUT
    // https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
    // Set TCP_USER_TIMEOUT to TCP_KEEPIDLE + TCP_KEEPINTVL * TCP_KEEPCNT.
    let keepintvl = socket2.keepalive_interval()?;
    let keepidle = socket2.keepalive_time()?;
    let keepcnt = socket2.keepalive_retries()?;
    socket2.set_tcp_user_timeout(Some(keepidle + keepintvl * keepcnt))?;
    Ok(())
}
