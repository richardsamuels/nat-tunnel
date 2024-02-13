use crate::{net as stnet, Result};
use std::net::SocketAddr;
use tnet::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::{error, info};

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
        // TODO using 1500 b/c it's the default MTU value on networks.
        // This needs refinement
        let reader = BufReader::with_capacity(1500, reader);
        let writer = BufWriter::with_capacity(1500, writer);

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
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = Vec::new();
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
                        data: buf,
                    };
                    self.reader.consume(len);
                    self.tx.send(d.into()).await?;
                    buf = Vec::new()
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn redirector_basic_fn() {
        let (tx, mut rx) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);
        let read = [1u8; 5];
        let reader = BufReader::new(&read[..]);

        let mut write = Vec::new();
        let writer = BufWriter::new(&mut write);
        let addr: SocketAddr = "127.0.0.1:123".parse().unwrap();
        let mut r = Redirector {
            id: addr,
            port: 12345,
            tx,
            rx: rx2,
            reader,
            writer,
        };

        tx2.send(stnet::Datagram{
            id: addr,
            port: 12345,
            data: vec![2,2,2,2]
        }.into()).await.unwrap();
        assert!(r.run().await.is_ok());

        // assert the buffer from read (simulating socket) was sent over the channel
        let stnet::RedirectorFrame::Datagram(rx) = rx.recv().await.unwrap() else {
            panic!("unexpected");
        };
        assert_eq!(rx.id, r.id);
        assert_eq!(rx.port, r.port);
        assert_eq!(rx.data, read);

        // assert the datagram was written to write (simulating writing to socket)
        assert_eq!(write, vec![2,2,2,2]);
    }
}
