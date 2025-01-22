use crate::net::frame::*;
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio_util::codec;

use std::marker::Unpin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type FramedLength<T> = tokio_util::codec::Framed<T, codec::LengthDelimitedCodec>;
pub type Framed<T> = tokio_serde::Framed<
    FramedLength<T>,
    Frame,
    Frame,
    tokio_serde::formats::MessagePack<Frame, Frame>,
>;

/// Helper to create correct codecs
pub fn frame<T>(stream: T) -> Framed<T>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // XXX: Warning, this codec means we don't need to care
    // about close_notify and TLS.
    let bytes_codec = codec::LengthDelimitedCodec::new();
    let bytes_frame = codec::Framed::new(stream, bytes_codec);

    let msgpack_codec = tokio_serde::formats::MessagePack::default();
    Framed::new(bytes_frame, msgpack_codec)
}

// TODO everything below here is yuck.
pub trait PeerAddr {
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
}

impl PeerAddr for tnet::TcpStream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.peer_addr()
    }
}

impl PeerAddr for tokio_rustls::TlsStream<tnet::TcpStream> {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            tokio_rustls::TlsStream::Client(_) => {
                let (stream, _) = self.get_ref();
                stream.peer_addr()
            }
            tokio_rustls::TlsStream::Server(_) => {
                let (stream, _) = self.get_ref();
                stream.peer_addr()
            }
        }
    }
}

impl PeerAddr for tokio_rustls::client::TlsStream<tnet::TcpStream> {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        let (stream, _) = self.get_ref();
        stream.peer_addr()
    }
}

impl PeerAddr for tokio_rustls::server::TlsStream<tnet::TcpStream> {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        let (stream, _) = self.get_ref();
        stream.peer_addr()
    }
}
