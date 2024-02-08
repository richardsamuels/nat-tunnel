use std::io::{BufRead, BufWriter, BufReader, Read, Write};
use tracing::{error, info};
use crate::Result;
use mio::net as mnet;
use mio::{Events, Interest, Poll, Token};

/// Fill buffer of `from` and write its contents to `to`
fn read_write<T, U>(from: &mut BufReader<T>, to: &mut BufWriter<U>)  -> std::io::Result<usize> where T: Read, U: Write {
    let buf = from.fill_buf()?;
    let len = buf.len();
    // len 0 indicates closed sockets
    if len != 0 {
        match to.write(buf) {
            Err(e) => {
                error!(cause = ?e, "Failed to write");
                return Err(e);
            },
            Ok(_) => {
                from.consume(len);
                to.flush()?;
            }
        };
    }
    Ok(len)
}

/// Read all data from left stream and write it to the right stream and vice
/// versa. Both streams should be connected
pub fn redirector(mut left_stream: mnet::TcpStream, mut right_stream: mnet::TcpStream) -> Result<()> {
    use std::io::ErrorKind;

    let mut poll = Poll::new()?;
    poll.registry().register(&mut left_stream, Token(0), Interest::WRITABLE)?;
    poll.registry().register(&mut right_stream, Token(1), Interest::WRITABLE)?;

    // Yield for writability on both sockets
    {
        let mut writable = [0u8; 2];
        let mut events = Events::with_capacity(2);
        loop {
            poll.poll(&mut events, None)?;

            for ev in &events {
                let token = ev.token();
                writable[token.0] = 1;
            }
            if writable[0] == 1 && writable[1] == 1  {
                break;
            }
        }
    }

    poll.registry().reregister(&mut left_stream, Token(0), Interest::READABLE)?;
    poll.registry().reregister(&mut right_stream, Token(1), Interest::READABLE)?;
    // TODO 1500 is the default ethernet payload size, but MTU
    // can vary so parameterize this
    let mut left_reader = BufReader::with_capacity(1500, &left_stream);
    let mut left_writer = BufWriter::with_capacity(1500, &left_stream);

    let mut right_reader = BufReader::with_capacity(1500, &right_stream);
    let mut right_writer = BufWriter::with_capacity(1500, &right_stream);

    let mut events = Events::with_capacity(128);
    'outer: loop {
        poll.poll(&mut events, None)?;
        for ev in &events {
            if ev.token() == Token(0) {
                loop {
                    match read_write(&mut left_reader, &mut right_writer) {
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Ok(0) => {
                            break 'outer;
                        }
                        Ok(_) => (),
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from left to right")
                        }
                    }
                }

            } else if ev.token() == Token(1) {
                loop {
                    match read_write(&mut right_reader, &mut left_writer) {
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Ok(0) => {
                            break 'outer;
                        }
                        Ok(_) => (),
                        Err(e) => {
                            error!(cause = ?e, "failed to redirect from right to left")
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
