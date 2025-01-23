use crate::string::LimitedString;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::vec::Vec;

#[derive(Debug, Deserialize, Serialize)]
pub enum RedirectorFrame {
    StartListener(SocketAddr, u16),
    Datagram(Datagram),
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

/// Helper to set keepalive on the underlying socket. (Not supported by the
/// std lib)
pub fn set_keepalive<T>(stream: &T, keepalive: bool) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    // you were supposed to better than this rust.
    use socket2::Socket;
    use std::os::fd::FromRawFd;

    let fd = stream.as_raw_fd();
    let dup_fd = unsafe { libc::dup(fd) };
    let socket2 = unsafe { Socket::from_raw_fd(dup_fd) };
    socket2.set_keepalive(keepalive)
}
