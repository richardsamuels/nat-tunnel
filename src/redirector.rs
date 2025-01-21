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

pub fn with_stream<R, W>(
    id: SocketAddr,
    port: u16,
    mtu: u16,
    token: CancellationToken,

    chan2net: mpsc::Receiver<stnet::RedirectorFrame>,
    net2chan: mpsc::Sender<stnet::RedirectorFrame>,
    stream: tnet::TcpStream,
) -> (
    Redirect2Channel<OwnedReadHalf>,
    Redirect2Network<OwnedWriteHalf>,
)
where
    R: AsyncRead + std::marker::Unpin,
    W: AsyncWrite + std::marker::Unpin,
{
    let (reader, writer) = stream.into_split();

    let r = Redirect2Channel::with_reader(id, port, mtu, token.clone(), reader, net2chan);
    let w = Redirect2Network::with_writer(id, mtu, token.clone(), writer, chan2net);
    (r, w)
}

pub struct Redirect2Network<W> {
    id: SocketAddr,
    #[allow(dead_code)]
    buffer_size: u16,
    token: CancellationToken,
    writer: BufWriter<W>,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
}

impl<W> Redirect2Network<W>
where
    W: AsyncWrite + std::marker::Unpin,
{
    pub fn with_writer(
        id: SocketAddr,
        _mtu: u16,
        token: CancellationToken,
        writer: W,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        // Look, what we're really trying to do here is calculate
        // MTU - PROTOCOL_OVERHEAD - (TCP/UDP Overhead) - Quic Overhead - TLS overhead
        // But i'm way too lazy to query these values in a cross platofmr way,
        // plumb the required info here, and figure out the math so....
        // Let's just use 1330, since ipv6 + QUIC says 1330 per packet
        // Citation: https://blog.apnic.net/2019/03/04/a-quick-look-at-quic/
        //let buffer_size = mtu - PROTOCOL_OVERHEAD;
        let buffer_size = 1330;
        let writer = BufWriter::with_capacity(buffer_size as usize, writer);

        Redirect2Network {
            id,
            buffer_size,
            token,
            rx,
            writer,
        }
    }

    pub async fn run(&mut self) {
        let span = trace_span!("channel2network", addr = ?self.id);
        let _guard = span.enter();

        let mut last_activity = std::time::Instant::now();
        let keepalive = Duration::from_secs(300);
        let mut interval = tokio::time::interval(keepalive);
        loop {
            tokio::select! {
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
        trace!("channel2network end");
    }
}

/// Reads data from stream, and send it along the `tx` channel
/// Reads data from rx chnnale, and send it along the stream
pub struct Redirect2Channel<R> {
    id: SocketAddr,
    port: u16,
    buffer_size: u16,
    token: CancellationToken,
    reader: BufReader<R>,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
}

impl<R> Redirect2Channel<R>
where
    R: AsyncRead + std::marker::Unpin,
{
    pub fn with_reader(
        id: SocketAddr,
        port: u16,
        _mtu: u16,
        token: CancellationToken,
        reader: R,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Self {
        // Look, what we're really trying to do here is calculate
        // MTU - PROTOCOL_OVERHEAD - (TCP/UDP Overhead) - Quic Overhead - TLS overhead
        // But i'm way too lazy to plumb all the required info, so
        // Let's just use 1330, since ipv6 + QUIC says 1330 per packet
        // Citation: https://blog.apnic.net/2019/03/04/a-quick-look-at-quic/
        //let buffer_size = mtu - PROTOCOL_OVERHEAD;
        let buffer_size = 1330;

        let reader = BufReader::with_capacity(buffer_size as usize, reader);

        Redirect2Channel {
            id,
            port,
            buffer_size,
            token,
            tx,
            reader,
        }
    }

    pub fn new(
        id: SocketAddr,
        port: u16,
        buffer_size: u16,
        token: CancellationToken,
        reader: BufReader<R>,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
    ) -> Redirect2Channel<R> {
        Redirect2Channel {
            id,
            port,
            token,
            reader,
            tx,
            buffer_size,
        }
    }
    pub async fn run(&mut self) {
        let span = trace_span!("network2channel", addr = ?self.id);
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

                _ = interval.tick() => {
                    if last_activity.elapsed() >= keepalive {
                        trace!("{} seconds passed without any activity. Closing.", keepalive.as_secs());
                        break
                    }
                }

                _ = self.token.cancelled() => break,
            }
        }
        trace!("network2channel end");
    }
}
