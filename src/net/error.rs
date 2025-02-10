use snafu::prelude::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("connection has died"))]
    ConnectionDead,
    #[snafu(display("connection refused"))]
    ConnectionRefused,
    #[snafu(display("quinn connection error: {source}"))]
    QuinnConnect {
        source: quinn::ConnectError,
        backtrace: snafu::Backtrace,
    },
    QuinnConnection {
        source: quinn::ConnectionError,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("network io error"))]
    Io {
        message: String,
        source: std::io::Error,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("{context} timed out"))]
    IoTimeout {
        context: String,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("msgpack decode error"))]
    MsgPackDecode {
        source: rmp_serde::decode::Error,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("msgpack encode error"))]
    MsgPackEncode {
        source: rmp_serde::encode::Error,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("received unexpected frame"))]
    UnexpectedFrame,
    #[snafu(display("{message}"))]
    Other {
        message: String,
        backtrace: snafu::Backtrace,
    },
}
