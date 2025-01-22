use crate::net::frame::*;
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
