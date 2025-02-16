use crate::net::error::*;
use crate::net::frame::*;
use futures::{SinkExt, TryStreamExt};
use snafu::ResultExt;
use std::marker::Unpin;
use std::net::SocketAddr;
use tokio_util::codec;

pub type FramedLength<T> = tokio_util::codec::Framed<T, codec::LengthDelimitedCodec>;
pub type Framed<T> = tokio_serde::Framed<
    FramedLength<T>,
    Frame,
    Frame,
    tokio_serde::formats::MessagePack<Frame, Frame>,
>;

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

#[derive(Debug, Hash, Clone)]
pub enum StreamId {
    Basic(SocketAddr),
    Quic(quinn::ConnectionId, quinn::StreamId, quinn::StreamId),
}

impl From<SocketAddr> for StreamId {
    fn from(id: SocketAddr) -> Self {
        StreamId::Basic(id)
    }
}

#[allow(type_alias_bounds)]
pub type AcceptedStream<T: Stream> = (StreamId, T);

pub struct Transport<T> {
    timeouts: crate::config::Timeout,
    framed: Framed<T>,
}

const MAGIC: u8 = 0xFA;
const PROTOCOL_VERSION: u8 = 0x00;
impl<T> Transport<T>
where
    T: Stream,
{
    pub fn new(timeouts: crate::config::Timeout, stream: T) -> Transport<T> {
        Transport {
            timeouts,
            framed: frame(stream),
        }
    }

    // Helo takes place outside of Framed because it's a rather
    // dangerous op. We need to validate the client as quickly as possible
    // w/o reading too much data
    pub async fn read_helo(&mut self) -> Result<Vec<u8>> {
        let stream = self.framed.get_mut().get_mut();
        let mut magic = [0x00; 4];

        let maybe_read =
            tokio::time::timeout(self.timeouts.auth, stream.read_exact(&mut magic)).await;

        match maybe_read {
            Err(_) => {
                return Err(crate::net::IoTimeoutSnafu {
                    context: "helo read",
                }
                .build());
            }
            Ok(Err(e)) => {
                return Err(e).with_context(|_| IoSnafu {
                    message: "failed to read helo",
                })
            }
            Ok(Ok(_)) => (),
        };

        if magic[0] != MAGIC {
            return Err(crate::net::error::UnexpectedFrameSnafu {}.build());
        }
        if magic[1] != PROTOCOL_VERSION {
            return Err(crate::net::error::UnexpectedFrameSnafu {}.build());
        }

        let size = u16::from_be_bytes([magic[2], magic[3]]);
        if size as usize > crate::config::PSK_MAX_LEN {
            tracing::error!("received key with invalid length {size}");
            return Err(crate::net::error::UnexpectedFrameSnafu {}.build());
        }

        let mut buf = vec![0x00; size.into()];

        let maybe_read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut buf),
        )
        .await;

        match maybe_read {
            Err(_) => {
                return Err(crate::net::IoTimeoutSnafu {
                    context: "helo read",
                }
                .build());
            }
            Ok(Err(e)) => {
                return Err(e).with_context(|_| IoSnafu {
                    message: "failed to read helo",
                })
            }
            Ok(Ok(_)) => (),
        };
        Ok(buf)
    }

    pub async fn send_helo(&mut self, key: &[u8]) -> Result<()> {
        let mut magic = vec![MAGIC, PROTOCOL_VERSION];
        let l = key.len();
        magic.extend(&(l as u16).to_be_bytes());
        magic.extend_from_slice(key);
        self.framed
            .get_mut()
            .get_mut()
            .write(&magic)
            .await
            .with_context(|_| crate::net::transport::IoSnafu {
                message: "failed to write helo",
            })?;

        Ok(())
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
                Err(e).with_context(|_| IoSnafu {
                    message: "failed to read frame",
                })
            }
            Ok(None) => Err(Error::ConnectionDead),
            Ok(Some(frame)) => Ok(frame),
        }
    }

    pub async fn write_frame(&mut self, t: Frame) -> Result<()> {
        self.framed.send(t).await.with_context(|_| IoSnafu {
            message: "failed to write frame",
        })?;
        //let future = tokio::time::timeout(self.timeouts.write, self.framed.send(t)).await;

        //match future {
        //    Err(_) => {
        //        return Err(crate::net::IoTimeoutSnafu {
        //            context: "frame write",
        //        }
        //        .build());
        //    }
        //    Ok(Err(e)) => {
        //        return Err(stnet::Error::Io {
        //            message: "failed to write frame".to_string(),
        //            source: e,
        //            backtrace: snafu::Backtrace::capture(),
        //        })
        //    }
        //    Ok(Ok(_)) => (),
        //};

        // XXX Flush MUST be called here. See tokio_rustls docs:
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/index.html#why-do-i-need-to-call-poll_flush
        self.framed.flush().await.with_context(|_| IoSnafu {
            message: "failed to flush",
        })
    }
}
