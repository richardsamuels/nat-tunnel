use crate::string::LimitedString;
use futures::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::vec::Vec;
use tokio::net as tnet;
use tokio_util::codec;

#[derive(Debug, Deserialize, Serialize)]
pub enum Frame {
    Auth(LimitedString<512>),
    Tunnels(Vec<u16>),
    NewProxy(u16),
    Datagram(Datagram),
    Kthxbai,
}

impl std::convert::From<Datagram> for Frame {
    fn from(value: Datagram) -> Self {
        Frame::Datagram(value)
    }
}

pub type FramedLength = tokio_util::codec::Framed<tnet::TcpStream, codec::LengthDelimitedCodec>;
pub type Framed = tokio_serde::Framed<
    FramedLength,
    Frame,
    Frame,
    tokio_serde::formats::MessagePack<Frame, Frame>,
>;

fn frame(stream: tnet::TcpStream) -> Framed {
    let len_codec = codec::LengthDelimitedCodec::new();
    let len_delimited = codec::Framed::new(stream, len_codec);

    let codec = tokio_serde::formats::MessagePack::default();
    Framed::new(len_delimited, codec)
}

pub struct Transport {
    framed: Framed,
}

impl Transport {
    pub fn new(stream: tnet::TcpStream) -> Transport {
        Transport {
            framed: frame(stream),
        }
    }

    pub fn peer_addr(&self) -> std::result::Result<std::net::SocketAddr, std::io::Error> {
        self.framed.get_ref().get_ref().peer_addr()
    }

    pub async fn read_frame(&mut self) -> std::result::Result<Frame, Error> {
        match self.framed.try_next().await {
            Err(e) => Err(e.into()),
            Ok(None) => Err(Error::ConnectionDead),
            Ok(Some(frame)) => Ok(frame),
        }
    }

    pub async fn write_frame(&mut self, t: Frame) -> Result<()> {
        match self.framed.send(t).await {
            Err(e) if reconnectable_err(&e) => {
                return Err(Error::ConnectionDead);
            }
            Err(e) => return Err(e.into()),
            Ok(()) => (),
        };
        self.framed.flush().await.map_err(|x| x.into())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Datagram {
    #[serde(rename = "i")]
    pub id: SocketAddr,
    #[serde(rename = "p")]
    pub port: u16,
    #[serde(rename = "d")]
    pub data: Vec<u8>,
}

/// Represents an authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct Auth {
    /// Pre-shared key
    #[serde(rename = "k")]
    pub psk: LimitedString<512>,
}

impl std::convert::From<std::string::String> for Auth {
    fn from(value: std::string::String) -> Self {
        Auth {
            psk: LimitedString(value),
        }
    }
}

impl Auth {
    pub fn new(psk: String) -> Auth {
        Auth {
            psk: LimitedString::<512>(psk),
        }
    }
}

/// Allows setting keepalive on the underlying socket.
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

#[derive(Debug)]
pub enum Error {
    ConnectionDead,
    Io(std::io::Error),
    MsgPackDecode(rmp_serde::decode::Error),
    MsgPackEncode(rmp_serde::encode::Error),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::MsgPackEncode(e) => write!(f, "{}", e),
            Error::MsgPackDecode(e) => write!(f, "{}", e),
            Error::Other(s) => write!(f, "{}", s),
            Error::ConnectionDead => write!(f, "simple_tunnel::net::Error::ConnectionDead"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::MsgPackDecode(e) => Some(e),
            Error::MsgPackEncode(e) => Some(e),
            _ => None,
        }
    }
}

impl std::convert::From<std::string::String> for Error {
    fn from(value: std::string::String) -> Self {
        Error::Other(value)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn reconnectable_err(err: &futures::io::Error) -> bool {
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
