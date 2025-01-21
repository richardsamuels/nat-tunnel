use crate::net as stnet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tnet::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net as tnet;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, trace_span};

// See tests/mtu.rs for an explanation of this magic number
pub const PROTOCOL_OVERHEAD: u16 = 53;

/// Reads data from stream, and send it along the `tx` channel
/// Reads data from rx chnnale, and send it along the stream
pub struct Redirector<R, W> {
    id: SocketAddr,
    port: u16,
    buffer_size: u16,
    token: CancellationToken,
    reader: BufReader<R>,
    writer: BufWriter<W>,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
}

impl Redirector<OwnedReadHalf, OwnedWriteHalf> {
    pub fn with_stream(
        id: SocketAddr,
        port: u16,
        mtu: u16,
        token: CancellationToken,
        stream: tnet::TcpStream,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        // Look, what we're really trying to do here is calculate
        // MTU - PROTOCOL_OVERHEAD - (TCP/UDP Overhead) - Quic Overhead - TLS overhead
        // But i'm way too lazy to plumb all the required info, so
        // Let's just use 1330, since ipv6 + QUIC says 1330 per packet
        // Citation: https://blog.apnic.net/2019/03/04/a-quick-look-at-quic/
        //let buffer_size = mtu - PROTOCOL_OVERHEAD;
        let buffer_size = 1330;

        let (reader, writer) = stream.into_split();
        let reader = BufReader::with_capacity(buffer_size as usize, reader);
        let writer = BufWriter::with_capacity(buffer_size as usize, writer);

        Redirector {
            id,
            port,
            buffer_size,
            token,
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
        buffer_size: u16,
        token: CancellationToken,
        reader: BufReader<R>,
        writer: BufWriter<W>,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Redirector<R, W> {
        Redirector {
            id,
            port,
            token,
            reader,
            writer,
            tx,
            rx,
            buffer_size,
        }
    }
    pub async fn run(&mut self) {
        let span = trace_span!("tunnel start", addr = ?self.id);
        let _guard = span.enter();

        let mut buf = vec![0u8; self.buffer_size as usize];
        let mut last_activity = std::time::Instant::now();
        let keepalive = Duration::from_secs(300);
        let mut interval = tokio::time::interval(keepalive);
        loop {
            tokio::select! {
                maybe_len = self.reader.read(&mut buf) => {
                    let len = match maybe_len {
                        Err(e) => {
                            error!(addr = ?self.id, cause = ?e, "failed to read from network");
                            break;
                        },
                        Ok(l) => l,
                    };
                    if len == 0 {
                        let _ = self.tx.send(stnet::RedirectorFrame::KillListener(self.id)).await;
                        trace!("read 0 bytes, ending redirector");
                        break
                    }
                    let d = stnet::Datagram {
                        id: self.id,
                        port: self.port,
                        data: buf[0..len].to_vec(),
                    };
                    self.reader.consume(len);
                    let _ = self.tx.send(d.into()).await;
                    last_activity = Instant::now();
                }

                maybe_data = self.rx.recv() => {
                    let data = match maybe_data {
                        None => break,
                        Some(stnet::RedirectorFrame::KillListener(_)) => {
                            trace!("killing listener on remote request");
                            break
                        }
                        Some(stnet::RedirectorFrame::Datagram(d)) => d,
                        Some(stnet::RedirectorFrame::StartListener(_, _)) => unreachable!(),
                    };
                    if let Err(e) = self.writer.write_all(&data.data).await {
                        error!(cause = ?e, "failed to write buffer");
                        break
                    };
                    if let Err(e) = self.writer.flush().await {
                        error!(cause = ?e, "failed to flush buffer");
                        break
                    }
                    last_activity = Instant::now();
                }

                _ = interval.tick() => {
                    if last_activity.elapsed() >= keepalive {
                        trace!("{} seconds passed without any activity. Closing.", keepalive.as_secs());
                        break
                    }
                }

                _ = self.token.cancelled() => break,
            }
        }
        self.rx.close();
        trace!("Tunnel end");
    }
}
