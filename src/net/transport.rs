use crate::net::error::*;
use crate::net::frame::*;
use futures::{SinkExt, TryStreamExt};
use std::net::SocketAddr;
use tokio::net as tnet;
use tokio_util::codec;

pub type FramedLength<T> = tokio_util::codec::Framed<T, codec::LengthDelimitedCodec>;
pub type Framed<T> = tokio_serde::Framed<
    FramedLength<T>,
    Frame,
    Frame,
    tokio_serde::formats::MessagePack<Frame, Frame>,
>;

/// Helper to create correct codecs
fn frame<T>(stream: T) -> Framed<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + std::marker::Unpin + PeerAddr,
{
    let len_codec = codec::LengthDelimitedCodec::new();
    let len_delimited = codec::Framed::new(stream, len_codec);

    let codec = tokio_serde::formats::MessagePack::default();
    Framed::new(len_delimited, codec)
}

pub struct Transport<T> {
    framed: Framed<T>,
}

impl<T> Transport<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + std::marker::Unpin + PeerAddr,
{
    pub fn new(stream: T) -> Transport<T> {
        Transport {
            framed: frame(stream),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.framed.get_ref().get_ref().addr()
    }

    pub async fn read_frame(&mut self) -> std::result::Result<Frame, Error> {
        match self.framed.try_next().await {
            Err(e) => Err(e.into()),
            Ok(None) => Err(Error::ConnectionDead),
            Ok(Some(frame)) => Ok(frame),
        }
    }

    pub async fn write_frame(&mut self, t: Frame) -> std::result::Result<(), Error> {
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

pub trait PeerAddr {
    fn addr(&self) -> std::io::Result<SocketAddr>;
}

impl PeerAddr for tnet::TcpStream {
    fn addr(&self) -> std::io::Result<SocketAddr> {
        self.peer_addr()
    }
}

impl PeerAddr for tokio_rustls::TlsStream<tnet::TcpStream> {
    fn addr(&self) -> std::io::Result<SocketAddr> {
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
    fn addr(&self) -> std::io::Result<SocketAddr> {
        let (stream, _) = self.get_ref();
        stream.peer_addr()
    }
}

impl PeerAddr for tokio_rustls::server::TlsStream<tnet::TcpStream> {
    fn addr(&self) -> std::io::Result<SocketAddr> {
        let (stream, _) = self.get_ref();
        stream.peer_addr()
    }
}
