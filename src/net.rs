use mio::net as mnet;
use mio::{Interest, Registry, Token};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};

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
/// Wrapper around a mio TcpStream for writing/reading MsgPack encoded data
pub struct NetBuf {
    stream: mnet::TcpStream,
}

impl NetBuf {
    pub fn new(stream: mnet::TcpStream) -> NetBuf {
        NetBuf { stream }
    }

    pub fn stream(&self) -> &mnet::TcpStream {
        &self.stream
    }

    /// encode and write T to internal stream
    pub fn write<T>(&mut self, val: &T) -> Result<()>
    where
        T: Serialize,
    {
        use rmp::encode::ValueWriteError as VWE;
        use rmp_serde::encode::Error as EnError;
        use std::io::ErrorKind;

        match rmp_serde::encode::write(&mut self.stream, val) {
            // TODO ugly
            Err(EnError::InvalidValueWrite(VWE::InvalidMarkerWrite(e)))
            | Err(EnError::InvalidValueWrite(VWE::InvalidDataWrite(e)))
                if e.kind() == ErrorKind::WouldBlock =>
            {
                Err(Error::WouldBlock)
            }
            Err(e) => Err(Error::MsgPackEncode(e)),
            Ok(_) => Ok(()),
        }
    }
    /// decode and read T from internal stream
    pub fn read<T>(&mut self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        use rmp_serde::decode::Error as DeError;
        use std::io::ErrorKind;

        match rmp_serde::decode::from_read(&mut self.stream) {
            Err(DeError::InvalidMarkerRead(e)) | Err(DeError::InvalidDataRead(e))
                if e.kind() == ErrorKind::WouldBlock =>
            {
                Err(Error::WouldBlock)
            }
            Err(e) => Err(Error::MsgPackDecode(e)),
            Ok(x) => Ok(x),
        }
    }

    pub fn eject(self) -> mnet::TcpStream {
        self.stream
    }

    pub fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.peek(buf)
    }
}

impl Write for NetBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Read for NetBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl mio::event::Source for NetBuf {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.stream.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.stream.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> std::io::Result<()> {
        self.stream.deregister(registry)
    }
}

/// Represents an incoming request on the remote's remote_port that will be
/// redirected to Remote's via_port.
#[derive(Debug, Deserialize, Serialize)]
pub struct PlzDial {
    pub remote_port: u16,
    pub via_port: u16,
}

/// Represents an authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct Auth {
    /// Pre-shared key
    pub psk: crate::LimitedString<512>,
}

impl Auth {
    pub fn new(psk: String) -> Auth {
        Auth {
            psk: crate::LimitedString::<512>(psk),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// Message sent when a client is shutting down
pub struct Kthxbai {}

#[derive(Debug)]
pub enum Error {
    WouldBlock,
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
            Error::WouldBlock => write!(f, "simple_tunnel::net::Error::WouldBlock"),
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
        if value.kind() == std::io::ErrorKind::WouldBlock {
            Error::WouldBlock
        } else {
            Error::Io(value)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Struct to map usize to T. The mapping enables using any Hashable type as a
/// mio Token
pub struct Tokens<T> {
    tokens: HashMap<usize, T>,
    rolling: usize,
}

impl<T> std::default::Default for Tokens<T> {
    fn default() -> Self {
        Tokens::<T>::new()
    }
}

impl<T> Tokens<T> {
    pub fn new() -> Tokens<T> {
        Tokens {
            tokens: HashMap::new(),
            rolling: 0,
        }
    }

    pub fn with_starting_offset(offset: usize) -> Tokens<T> {
        Tokens {
            tokens: HashMap::new(),
            rolling: offset,
        }
    }

    /// Insert a value v and return a usize that can be used with Token
    pub fn insert(&mut self, v: T) -> Option<usize> {
        let k = self.rolling;
        self.rolling += 1;
        if self.tokens.contains_key(&k) {
            return None;
        }
        match self.tokens.insert(k, v) {
            None => Some(k),
            Some(_) => unreachable!(),
        }
    }
    pub fn remove(&mut self, k: usize) -> Option<T> {
        self.tokens.remove(&k)
    }
    pub fn get(&self, k: usize) -> Option<&T> {
        self.tokens.get(&k)
    }
}
