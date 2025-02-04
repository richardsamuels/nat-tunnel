use crate::net as stnet;
use crate::net::error::*;
use crate::net::frame::*;
use futures::{SinkExt, TryStreamExt};
use std::marker::Unpin;
use std::net::SocketAddr;
use tokio_util::codec;
use tracing::error;

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
    T: Stream,
{
    let bytes_codec = codec::LengthDelimitedCodec::new();
    let bytes_frame = codec::Framed::new(stream, bytes_codec);

    let msgpack_codec = tokio_serde::formats::MessagePack::default();
    Framed::new(bytes_frame, msgpack_codec)
}

pub trait Stream: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Sync + Send + Unpin {}
impl<T: tokio::io::AsyncWriteExt + tokio::io::AsyncReadExt + Sync + Send + Unpin> Stream for T {}
pub type StreamId = SocketAddr;
#[allow(type_alias_bounds)]
pub type AcceptedStream<T: Stream> = (StreamId, T);

pub struct Transport<T> {
    framed: Framed<T>,
}

impl<T> Transport<T>
where
    T: Stream,
{
    pub fn new(stream: T) -> Transport<T> {
        Transport {
            framed: frame(stream),
        }
    }

    //pub async fn shutdown(&mut self) -> std::io::Result<()> {
    //    self.framed.get_mut().get_mut().shutdown().await
    //}

    pub async fn read_frame(&mut self) -> Result<Frame> {
        match self.framed.try_next().await {
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(Error::ConnectionDead);
                }
                Err(stnet::Error::Io {
                    message: "failed to read frame".to_string(),
                    source: e,
                    backtrace: snafu::Backtrace::capture(),
                })
            }
            Ok(None) => Err(Error::ConnectionDead),
            Ok(Some(frame)) => Ok(frame),
        }
    }

    pub async fn write_frame(&mut self, t: Frame) -> Result<()> {
        let future =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.framed.send(t)).await;

        match future {
            Err(_) => {
                error!("write timeout");
                return Err(stnet::Error::Other {
                    message: "write timeout".to_string(),
                    backtrace: snafu::Backtrace::capture(),
                });
            }
            Ok(Err(e)) if reconnectable_err(&e) => {
                return Err(Error::ConnectionDead);
            }
            Ok(Err(e)) => {
                return Err(stnet::Error::Io {
                    message: "failed to write frame".to_string(),
                    source: e,
                    backtrace: snafu::Backtrace::capture(),
                })
            }
            Ok(Ok(_)) => (),
        };

        // XXX Flush MUST be called here. See tokio_rustls docs:
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/index.html#why-do-i-need-to-call-poll_flush
        self.framed.flush().await.map_err(|e| stnet::Error::Io {
            message: "failed to flush".to_string(),
            source: e,
            backtrace: snafu::Backtrace::capture(),
        })
    }
}
