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

pub async fn quinn(
    token: CancellationToken,
    endpoint: &quinn::Endpoint,
    addrs: &[SocketAddr],
    expected_host: &str,
) -> stnet::Result<Option<quinn::Connection>> {
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
                    try_quinn(endpoint, v6, expected_host).boxed(),
                    with_delay(endpoint, v4, expected_host, try_quinn).boxed(),
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
                    maybe = try_quinn(endpoint, x, expected_host) => {
                        match maybe {
                            Err(e) => {
                                error!(e=?e, addr=?x, "connection failed");
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

pub async fn try_quinn(
    endpoint: &quinn::Endpoint,
    addr: &SocketAddr,
    expected_host: &str,
) -> stnet::Result<quinn::Connection> {
    trace!(addr=?addr, "trying to connect via QUIC");
    endpoint
        .connect(*addr, expected_host)
        .with_context(|_| stnet::QuinnConnectSnafu {})?
        .await
        .with_context(|_| stnet::QuinnConnectionSnafu {})
}

async fn with_delay<'a, F, Fut>(
    endpoint: &'a quinn::Endpoint,
    addr: &'a SocketAddr,
    expected_host: &'a str,
    f: F,
) -> stnet::Result<quinn::Connection>
where
    F: Fn(&'a quinn::Endpoint, &'a SocketAddr, &'a str) -> Fut,
    Fut: Future<Output = stnet::Result<quinn::Connection>>,
{
    let mut interval = time::interval_at(
        Instant::now() + Duration::from_millis(200),
        Duration::from_millis(200),
    );
    interval.tick().await;
    f(endpoint, addr, expected_host).await
}
