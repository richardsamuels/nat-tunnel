use crate::net as stnet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, trace};

// See tests/mtu.rs for an explanation of this magic number
pub const PROTOCOL_OVERHEAD: u16 = 53;

/// Reads data from stream, and send it along the `tx` channel
/// Reads data from rx channel, and send it along the stream
pub struct Redirector<T: stnet::Stream> {
    id: SocketAddr,
    port: u16,
    token: CancellationToken,
    buffer_size: usize,
    stream: T,
    tx: mpsc::Sender<stnet::RedirectorFrame>,
    rx: mpsc::Receiver<stnet::RedirectorFrame>,
}

impl<T> Redirector<T>
where
    T: stnet::Stream,
{
    pub fn with_stream(
        id: SocketAddr,
        port: u16,
        _mtu: u16,
        token: CancellationToken,
        stream: T,
        tx: mpsc::Sender<stnet::RedirectorFrame>,
        rx: mpsc::Receiver<stnet::RedirectorFrame>,
    ) -> Self {
        // Look, what we're really trying to do here is calculate
        // MTU - PROTOCOL_OVERHEAD - (TCP/UDP Overhead) - Quic Overhead - TLS overhead - Ethernet
        // overhead.
        // But i'm way too lazy to do this math, so et's just use 1330, since
        // ipv6 + QUIC says 1330 per packet  and that appears to be the smallest
        // possible packet we'll send over the network.
        // Citation: https://blog.apnic.net/2019/03/04/a-quick-look-at-quic/
        //let buffer_size = mtu - PROTOCOL_OVERHEAD;
        let buffer_size = 1330 - PROTOCOL_OVERHEAD as usize;

        Redirector {
            stream,
            buffer_size,
            id,
            port,
            token,
            tx,
            rx,
        }
    }
    pub async fn read(
        &mut self,
        maybe_n: std::io::Result<usize>,
        &mut ref mut buf: &mut Vec<u8>,
        &mut ref mut last_activity: &mut std::time::Instant,
    ) -> Option<bool> {
        let n = match maybe_n {
            Err(e) => {
                error!(addr = ?self.id, cause = ?e, "failed to read from network");
                return Some(false);
            }
            Ok(l) => l,
        };
        if n == 0 {
            let _ = self
                .tx
                .send(stnet::RedirectorFrame::KillListener(self.id))
                .await;
            trace!("read 0 bytes, ending redirector");
            return Some(true);
        }
        let mut data = buf.clone();
        data.resize(n, 0);
        let d = stnet::Datagram {
            id: self.id,
            port: self.port,
            data,
        };
        *buf = vec![0; self.buffer_size];
        let _ = self.tx.send(d.into()).await;
        *last_activity = Instant::now();
        None
    }

    pub async fn write(
        &mut self,
        maybe_data: Option<stnet::RedirectorFrame>,
        &mut ref mut last_activity: &mut std::time::Instant,
    ) -> Option<bool> {
        let data = match maybe_data {
            None => return Some(true),
            Some(stnet::RedirectorFrame::Datagram(d)) => d,
            // These packets should never reach a redirector
            Some(stnet::RedirectorFrame::KillListener(_)) => unreachable!(),
            Some(stnet::RedirectorFrame::StartListener(_, _)) => unreachable!(),
        };
        if let Err(e) = self.stream.write_all(&data.data).await {
            error!(cause = ?e, "failed to write buffer");
            return Some(false);
        };
        if let Err(e) = self.stream.flush().await {
            error!(cause = ?e, "failed to flush buffer");
            return Some(false);
        }
        *last_activity = Instant::now();
        None
    }

    #[tracing::instrument(name = "Redirector", level = "trace", skip_all)]
    pub async fn run(&mut self) {
        let mut last_activity = std::time::Instant::now();
        let keepalive = Duration::from_secs(300);
        let mut interval = tokio::time::interval(keepalive);
        let mut buf = vec![0; self.buffer_size];
        let mut write_done = false;
        let mut read_done = false;
        // This is disgusting, but it lets half closed connections function correctly
        loop {
            tokio::select! {
                maybe_n = self.stream.read(&mut buf) => {
                    if let Some(s) = self.read(maybe_n, &mut buf, &mut last_activity).await {
                        if s {
                            read_done = true;
                        } else {
                            write_done = true;
                            read_done = true;
                        }
                        break
                    }
                }

                maybe_data = self.rx.recv() => {
                    if let Some(s) = self.write(maybe_data, &mut last_activity).await {
                        if s {
                            write_done = true;
                        } else {
                            write_done = true;
                            read_done = true;
                        }
                        break
                    }
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

        if read_done && !write_done {
            loop {
                tokio::select! {
                    maybe_data = self.rx.recv() => {
                        if self.write(maybe_data, &mut last_activity).await.is_some() {
                            break
                        }
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
        }

        if write_done && !read_done {
            loop {
                tokio::select! {
                    maybe_n = self.stream.read(&mut buf) => {
                        if self.read(maybe_n, &mut buf, &mut last_activity).await.is_some() {
                            break
                        }
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
        }
        self.rx.close();
        trace!("Tunnel end");
    }
}
