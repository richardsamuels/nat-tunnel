use crate::net as stnet;
use futures::Future;
use futures::FutureExt;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use snafu::ResultExt;
use std::net::SocketAddr;
use tokio::time::{self, Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{error, trace};

pub async fn tcp(
    token: CancellationToken,
    addrs: Vec<SocketAddr>,
    port: u16,
) -> stnet::Result<Option<tokio::net::TcpStream>> {
    let ipv6_addrs = addrs
        .iter()
        .filter(|addr| matches!(addr, SocketAddr::V6(_)))
        .peekable();
    let ipv4_addrs = addrs
        .iter()
        .filter(|addr| matches!(addr, SocketAddr::V4(_)))
        .peekable();

    for elem in ipv6_addrs.zip_longest(ipv4_addrs) {
        let stream = match elem {
            // race between ipv6 and ipv4 connections with ipv4 having a delayed start
            Both(v6, v4) => {
                let mut futs = vec![
                    try_tcp(v6, port).boxed(),
                    with_delay(v4, port, try_tcp).boxed(),
                ];
                let ret = loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            return Ok(None)
                        }

                        ret = futures::future::select_all(futs) => {
                            let (item_resolved, _, remaining_futures) = ret;
                            if let Ok(x) = item_resolved {
                                break Some(x);
                            }
                            futs = remaining_futures;
                        }
                    }

                    if futs.is_empty() {
                        break None;
                    }
                };

                if ret.is_none() {
                    continue;
                }
                ret.unwrap()
            }
            // otherwise try the remaining ones one by one
            Left(x) | Right(x) => {
                tokio::select! {
                    _ = token.cancelled() => {
                        return Ok(None)
                    }
                    maybe = try_tcp(x, port) => {
                        match maybe {
                            Err(e) => {
                                error!(e=?e, addr=?x, port=port, "connection failed");
                                continue
                            }
                            Ok(s) => s
                        }
                    }
                }
            }
        };

        return Ok(Some(stream));
    }

    Ok(None)
}

async fn try_tcp(addr: &SocketAddr, port: u16) -> stnet::Result<tokio::net::TcpStream> {
    trace!(addr=?addr, port=port, "trying connection via TCP");
    let addr = SocketAddr::new(addr.ip(), port);
    tokio::net::TcpStream::connect(addr)
        .await
        .with_context(|_| stnet::IoSnafu {
            message: format!("Failed to connect to {addr:?}"),
        })
}

async fn with_delay<'a, F, Fut>(
    addr: &'a SocketAddr,
    port: u16,
    f: F,
) -> stnet::Result<tokio::net::TcpStream>
where
    F: Fn(&'a SocketAddr, u16) -> Fut,
    Fut: Future<Output = stnet::Result<tokio::net::TcpStream>>,
{
    let mut interval = time::interval_at(
        Instant::now() + Duration::from_millis(200),
        Duration::from_millis(200),
    );
    interval.tick().await;
    f(&addr, port).await
}
