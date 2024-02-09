use crate::redirector;
use crate::{config, net as stnet, Result};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::io::Write;
use tracing::{error, info};
use tokio::net as tnet;
use tokio_util::codec;
use tokio_serde::Framed;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};
use serde::{Deserialize, Serialize};
use futures::sink::Sink;
use futures::sink::SinkExt;
use crate::net::Frame;
use crate::net;
use futures::TryStreamExt;


pub struct Client {
    transport: crate::net::Framed,
}

impl Client {
    pub fn new(stream: tnet::TcpStream) -> Result<Client> {
        stnet::set_keepalive(&stream, true)?;
        let len_codec = LengthDelimitedCodec::new();
        let len_delimited = codec::Framed::new(stream, len_codec);

        let codec = tokio_serde::formats::MessagePack::default();
        let transport = Framed::new(len_delimited, codec);

        let c = Client {
            transport
        };
        Ok(c)
    }

    pub async fn push_tunnel_config(&mut self, c: &config::ClientConfig) -> Result<()> {
        self.transport.send(Frame::Auth(c.psk.clone().into())).await?;
        self.transport.flush().await?;

        let tunnels = {
            let mut out = Vec::new();
            for tunnel in &c.tunnels {
                out.push(tunnel.remote_port);
            }
            out
        };
        self.transport.send(Frame::Tunnels(tunnels)).await?;
        self.transport.flush().await?;
        info!("Pushed tunnel config to remote");
        Ok(())
    }

    pub async fn run(&mut self, c: &config::ClientConfig) -> Result<()> {
        let frame: Frame = match self.transport.try_next().await {
            Err(e) => {
                error!(cause = ?e, "failed to read");
                return Err(e.into());
            }
            Ok(None) => return Err("".into()),
            Ok(Some(f)) => f
        };

        match frame {
            Frame::Kthxbai => Ok(()),
            Frame::Dial(pd) => {
                let from_addr: SocketAddr =
                    format!("{}:{}", &c.addr, &pd.via_port).parse().unwrap();
                let local_port: u16 = {
                    let mut out = 0;
                    for t in &c.tunnels {
                        if t.remote_port == pd.remote_port {
                            out = t.local_port;
                            break;
                        }
                    }
                    out
                };
                let to_addr: SocketAddr =
                    format!("127.0.0.1:{}", local_port).parse().unwrap();
                info!(dial = ?pd, local_port = local_port, from = ?from_addr, to = ?to_addr, "Received dial request");
                let from_stream = match tnet::TcpStream::connect(from_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(cause = ?e, from = ?from_addr, "Failed to connect to remote");
                        return Err(e.into());
                    }
                };
                let to_stream = match tnet::TcpStream::connect(to_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(cause = ?e, to = ?to_addr, "Failed to connect to b");
                        return Err(e.into());
                    }
                };

                // TODO auth
                //let mut transport = net::NetBuf::new(from_stream);
                //let auth: net::Auth = net::Auth::new(c.psk.clone());
                //transport.write(&auth)?;
                //transport.flush()?;
                //std::thread::spawn(|| redirector::redirector(transport.eject(), to_stream));
                //std::thread::spawn(|| redirector::redirector(from_stream, to_stream));
                Ok(())
            },
            _ => unreachable!(),
        }
    }
}
