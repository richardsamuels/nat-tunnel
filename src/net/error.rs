use snafu::prelude::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("connection has died"))]
    ConnectionDead,
    #[snafu(display("connection refused"))]
    ConnectionRefused,
    #[snafu(display("network io error"))]
    Io {
        message: String,
        source: std::io::Error,
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

//impl std::convert::From<std::string::String> for Error {
//    fn from(value: std::string::String) -> Self {
//        Error::Other { source: value }
//    }
//}

//impl std::convert::From<&str> for Error {
//    fn from(value: &str) -> Self {
//        Error::Other {
//            source: value.to_string(),
//        }
//    }
//}

//impl std::convert::From<std::io::Error> for Error {
//    fn from(value: std::io::Error) -> Self {
//        Error::Io { source: value }
//    }
//}
