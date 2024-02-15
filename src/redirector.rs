use crate::{net as stnet, Result};
use std::net::SocketAddr;
use tnet::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::{error, info, trace};

// TODO using 1500 b/c it's the default MTU value on networks.
// This needs refinement
const BUFFER_CAPACITY: usize = 1500;

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
    R: AsyncRead + std::marker::Unpin,
    W: AsyncWrite + std::marker::Unpin,
{
    pub fn new(
        id: SocketAddr,
        port: u16,
        reader: BufReader<R>,
        writer: BufWriter<W>,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Redirector<R, W> {
        Redirector {
            id,
            port,
            reader,
            writer,
            tx,
            rx,
        }
    }
    pub async fn run(&mut self) -> Result<()> {
        trace!(addr = ?self.id, "Tunnel start");
        let mut buf = [0u8; BUFFER_CAPACITY];
        loop {
            tokio::select! {
                maybe_len = self.reader.read(&mut buf) => {
                    let len = match maybe_len {
                        Err(e) => {
                            error!(cause = ?e, "failed to read from network");
                            break;
                        },
                        Ok(l) => l,
                    };
                    if len == 0 {
                        self.tx.send(stnet::RedirectorFrame::KillListener(self.id)).await?;
                        break
                    }
                    let d = stnet::Datagram {
                        id: self.id,
                        port: self.port,
                        data: buf[0..len].to_vec(),
                    };
                    self.reader.consume(len);
                    self.tx.send(d.into()).await?;
                }

                maybe_data = self.rx.recv() => {
                    let data = match maybe_data {
                        None => break,
                        Some(stnet::RedirectorFrame::KillListener(_)) => {
                            info!(id = ?self.id, "killing listener");
                            break
                        }
                        Some(stnet::RedirectorFrame::Datagram(d)) => d,
                    };
                    self.writer.write_all(&data.data).await?;
                    self.writer.flush().await?;
                }
            }
        }
        self.rx.close();
        trace!(addr = ?self.id, "Tunnel end");
        Ok(())
    }
}
