use crate::{net as stnet, Result};
use std::net::SocketAddr;
use tnet::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::{error, info};

// TODO using 1500 b/c it's the default MTU value on networks.
// This needs refinement
const BUFFER_CAPACITY: usize = 1500;

pub struct RedirectorReadHalf<R> {
    id: SocketAddr,
    port: u16,
    reader: R,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
}

impl<R> RedirectorReadHalf<R>
where
    R: AsyncRead + std::marker::Unpin,
{
    pub fn new(
        id: SocketAddr,
        port: u16,
        reader: R,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        RedirectorReadHalf {
            id,
            port,
            tx,
            reader,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; BUFFER_CAPACITY];
        loop {
            let len = self.reader.read(&mut buf).await?;
            if len == 0 {
                self.tx
                    .send(stnet::RedirectorFrame::KillListener(self.id))
                    .await?;
                break;
            }
            let d = stnet::Datagram {
                id: self.id,
                port: self.port,
                data: buf[0..len].to_vec(),
            };
            self.tx.send(d.into()).await?;
        }
        Ok(())
    }
}

pub struct RedirectorWriteHalf<W> {
    id: SocketAddr,
    writer: W,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
}

impl<W> RedirectorWriteHalf<W>
where
    W: AsyncWrite + std::marker::Unpin,
{
    pub fn new(id: SocketAddr, writer: W, rx: mpsc::Receiver<stnet::RedirectorFrame>) -> Self {
        RedirectorWriteHalf { id, rx, writer }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let data = match self.rx.recv().await {
                None => break,
                Some(stnet::RedirectorFrame::KillListener(_)) => {
                    info!(id = ?self.id, "killing listener");
                    break;
                }
                Some(stnet::RedirectorFrame::Datagram(d)) => d,
            };
            self.writer.write_all(&data.data).await?;
            self.writer.flush().await?;
        }
        Ok(())
    }
}

/// Reads data from stream, and send it along the `tx` channel
/// Reads data from rx chnnale, and send it along the stream
pub struct Redirector<R, W> {
    id: SocketAddr,
    write: RedirectorWriteHalf<BufWriter<W>>,
    read: RedirectorReadHalf<BufReader<R>>,
}

impl Redirector<OwnedReadHalf, OwnedWriteHalf> {
    pub fn with_stream(
        id: SocketAddr,
        port: u16,
        stream: tnet::TcpStream,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        let (reader, writer) = stream.into_split();
        let reader = BufReader::with_capacity(BUFFER_CAPACITY, reader);
        let writer = BufWriter::with_capacity(BUFFER_CAPACITY, writer);
        let write = RedirectorWriteHalf::new(id, writer, rx);
        let read = RedirectorReadHalf::new(id, port, reader, tx);

        Redirector { id, read, write }
    }
}

impl<R, W> Redirector<R, W>
where
    R: AsyncRead + std::marker::Unpin + std::marker::Send + std::marker::Sync,
    W: AsyncWrite + std::marker::Unpin + std::marker::Send + std::marker::Sync,
{
    pub fn new(
        id: SocketAddr,
        port: u16,
        reader: R,
        writer: W,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        let reader = BufReader::with_capacity(BUFFER_CAPACITY, reader);
        let writer = BufWriter::with_capacity(BUFFER_CAPACITY, writer);

        let write = RedirectorWriteHalf::new(id, writer, rx);
        let read = RedirectorReadHalf::new(id, port, reader, tx);

        Redirector { id, read, write }
    }

    pub fn into_split(
        self,
    ) -> (
        RedirectorReadHalf<BufReader<R>>,
        RedirectorWriteHalf<BufWriter<W>>,
    ) {
        (self.read, self.write)
    }

    pub async fn run(&mut self) -> SocketAddr {
        tokio::join!(
            async {
                if let Err(e) = self.read.run().await {
                    error!(cause = ?e, addr = ?self.id, "tunnel read error");
                }
            },
            async {
                if let Err(e) = self.write.run().await {
                    error!(cause = ?e, addr = ?self.id, "tunnel writer error");
                }
            },
        );
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::RedirectorFrame as RF;

    #[tokio::test]
    async fn redirector() {
        let id: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let port = 0;

        let read = [1u8; 5];
        let write = vec![];
        let (to_writer, from_test) = mpsc::channel(5);
        let (to_test, mut from_reader) = mpsc::channel(5);

        let _ = to_writer
            .send(RF::Datagram(crate::net::Datagram {
                id,
                port: 0,
                data: vec![3, 3, 3, 3, 3],
            }))
            .await;
        let _ = to_writer
            .send(crate::net::RedirectorFrame::KillListener(id))
            .await;
        let mut r = Redirector::new(id, port, &read[..], write, to_test, from_test);
        let id_ret = r.run().await;
        assert_eq!(id_ret, id);

        assert_eq!(r.write.writer.into_inner(), vec![3, 3, 3, 3, 3]);

        let frame0 = match from_reader.recv().await.expect("missing frame") {
            RF::Datagram(f) => f,
            _ => panic!("wrong frame"),
        };

        assert_eq!(frame0.data, vec![1, 1, 1, 1, 1]);
    }
}
