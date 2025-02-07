use crate::net as stnet;
use std::collections::{HashMap, HashSet};
use std::marker::Unpin;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

pub type TunnelChannels = HashMap<SocketAddr, mpsc::Sender<stnet::RedirectorFrame>>;
pub type ActiveTunnels = HashSet<u16>;

pub struct QuicBox {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBox {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicBox { send, recv }
    }

    pub fn id(&self) -> (quinn::StreamId, quinn::StreamId) {
        (self.send.id(), self.recv.id())
    }
}
impl Unpin for QuicBox {}

impl tokio::io::AsyncWrite for QuicBox {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

impl tokio::io::AsyncRead for QuicBox {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
