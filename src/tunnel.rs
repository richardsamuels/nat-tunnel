use crate::{net as stnet, Result};
use std::net::SocketAddr;
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tracing::error;

pub struct TunnelHandler {
    id: SocketAddr,
    port: u16,
    stream: tnet::TcpStream,
    to_remote: mpsc::Sender<stnet::Datagram>,
    from_remote: mpsc::Receiver<stnet::Datagram>,
}

impl TunnelHandler {
    pub fn new(
        id: SocketAddr,
        port: u16,
        stream: tnet::TcpStream,
        to_remote: mpsc::Sender<stnet::Datagram>,
        from_remote: mpsc::Receiver<stnet::Datagram>,
    ) -> Self {
        TunnelHandler {
            id,
            port,
            stream,
            to_remote,
            from_remote,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let (b_reader, b_writer) = self.stream.split();

        let mut b_reader = BufReader::with_capacity(1500, b_reader);
        let mut b_writer = BufWriter::with_capacity(1500, b_writer);

        loop {
            tokio::select! {
                maybe_buf = b_reader.fill_buf() => {
                    let buf = match maybe_buf {
                        Err(e) => {
                            error!(cause = ?e, "failed to read from network");
                            break;
                        },
                        Ok(buf) => buf,
                    };
                    let len = buf.len();
                    if len == 0 {
                        break;
                    }
                    let d = stnet::Datagram {
                        id: self.id,
                        port: self.port,
                        data: buf.to_vec(), // TODO nooooooooooo
                    };
                    b_reader.consume(len);
                    self.to_remote.send(d).await?;
                }

                maybe_data = self.from_remote.recv() => {
                    let data: stnet::Datagram = match maybe_data {
                        None => break,
                        Some(data) => data,
                    };
                    if data.data.is_empty() {
                        break;
                    }
                    b_writer.write_all(&data.data).await?;
                    b_writer.flush().await?;
                }
            }
        }

        Ok(())
    }
}
