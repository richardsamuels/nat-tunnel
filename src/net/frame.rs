use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
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
    Auth(AuthKey),
    Tunnels(Vec<u16>),
    ListenerStart(SocketAddr),
    Redirector(RedirectorFrame),
    ListenerEnd(SocketAddr),
    Kthxbai,
    Heartbeat,
}

#[derive(Deserialize, Serialize)]
pub struct AuthKey(Vec<u8>);

// custom impl because we must not leak auth key
impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthKey").finish()
    }
}

impl DerefMut for AuthKey {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Deref for AuthKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<Vec<u8>> for AuthKey {
    fn from(item: Vec<u8>) -> Self {
        AuthKey(item)
    }
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
    //socket2.set_tcp_user_timeout(Some(keepidle + keepintvl * keepcnt))?;
    Ok(())
}
