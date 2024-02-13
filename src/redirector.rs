use crate::{net as stnet, Result};
use std::net::SocketAddr;
use tnet::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
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
    fn new(id: SocketAddr, port: u16, reader: R, tx: mpsc::Sender<stnet::RedirectorFrame>) -> Self {
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
    port: u16,
    reader: BufReader<R>,
    writer: BufWriter<W>,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
}

impl Redirector<OwnedReadHalf, OwnedWriteHalf> {
    pub fn new(
        id: SocketAddr,
        port: u16,
        stream: tnet::TcpStream,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        let (reader, writer) = stream.into_split();
        let reader = BufReader::with_capacity(BUFFER_CAPACITY, reader);
        let writer = BufWriter::with_capacity(BUFFER_CAPACITY, writer);

        Redirector {
            id,
            port,
            tx,
            rx,
            reader,
            writer,
        }
    }
}

impl<R, W> Redirector<R, W>
where
    R: AsyncRead + std::marker::Unpin + std::marker::Send,
    W: AsyncWrite + std::marker::Unpin + std::marker::Send,
{
    pub fn into_split(
        self,
    ) -> (
        RedirectorReadHalf<BufReader<R>>,
        RedirectorWriteHalf<BufWriter<W>>,
    ) {
        let read = RedirectorReadHalf::new(self.id, self.port, self.reader, self.tx);
        let write = RedirectorWriteHalf::new(self.id, self.writer, self.rx);
        (read, write)
    }
}
pub async fn redirector(
    id: SocketAddr,
    port: u16,
    stream: tnet::TcpStream,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
) -> SocketAddr {
    let h = Redirector::new(id, port, stream, tx, rx);
    let (mut read, mut write) = h.into_split();
    let mut set = JoinSet::new();
    set.spawn(async move {
        if let Err(e) = read.run().await {
            error!(cause = ?e, addr = ?id, "tunnel read error");
        }
    });
    set.spawn(async move {
        if let Err(e) = write.run().await {
            error!(cause = ?e, addr = ?id, "tunnel writer error");
        }
    });
    set.join_next().await;
    set.join_next().await;
    id
}
