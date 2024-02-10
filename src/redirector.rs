use crate::Result;
use tracing::error;
use tokio::net as tnet;

pub struct RedirectorHandler {
    left: tnet::TcpStream,
    right: tnet::TcpStream,
}

impl RedirectorHandler {
    pub fn new(left: tnet::TcpStream, right: tnet::TcpStream) -> Self {
        RedirectorHandler { left, right }
    }

    pub async fn run(&mut self) -> Result<()> {
        use tokio::io::{BufWriter, BufReader};
        error!("actual redirecting");

        // Yield for writability on both sockets
        //self.left.writable().await?;
        //self.right.writable().await?;

        let (left_r, left_w) = self.left.split();
        let (right_r, right_w) = self.right.split();

        // TODO 1500 is the default ethernet payload size, but MTU
        // can vary so maybe parameterize this
        let mut left_reader = BufReader::with_capacity(1500, left_r);
        let mut left_writer = BufWriter::with_capacity(1500, left_w);
        let mut right_reader = BufReader::with_capacity(1500, right_r);
        let mut right_writer = BufWriter::with_capacity(1500, right_w);

        loop {
            tokio::select! {
                lr = read_write(&mut left_reader, &mut right_writer) => {
                    match lr {
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from left to right");
                            continue
                        },
                        Ok(0) => break,
                        Ok(_) => continue
                    }
                }
                rl = read_write(&mut right_reader, &mut left_writer) => {
                    match rl {
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from right to left");
                            continue
                        },
                        Ok(0) => break,
                        Ok(_) => continue
                    }
                }
            };
        }

        Ok(())
    }
}

async fn read_write<T, U>(from: &mut T, to: &mut U) -> std::io::Result<usize>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncBufReadExt + std::marker::Unpin,
    U: tokio::io::AsyncWriteExt + std::marker::Unpin,
{
    let buf = from.fill_buf().await?;
    let len = buf.len();
    // len 0 indicates closed sockets
    if len != 0 {
        match to.write(buf).await {
            Err(e) => {
                error!(cause = ?e, "Failed to write");
                return Err(e);
            }
            Ok(_) => {
                from.consume(len);
                to.flush().await?;
            }
        };
    }
    Ok(len)
}

