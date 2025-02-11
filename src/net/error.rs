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
    Rustls {
        source: rustls::Error,
    },
    #[snafu(display("{source}"))]
    RustPkiDnsName {
        source: rustls_pki_types::InvalidDnsNameError,
    },
}

impl From<rustls::Error> for Error {
    fn from(source: rustls::Error) -> Self {
        Error::Rustls { source }
    }
}

impl From<quinn::ConnectionError> for Error {
    fn from(source: quinn::ConnectionError) -> Self {
        Error::QuinnConnection {
            source,
            backtrace: snafu::Backtrace::capture(),
        }
    }
}

impl From<rustls_pki_types::InvalidDnsNameError> for Error {
    fn from(source: rustls_pki_types::InvalidDnsNameError) -> Self {
        Error::RustPkiDnsName { source }
    }
}

impl Error {
    pub fn reconnectable_err(&self) -> bool {
        use Error::*;
        match self {
            Io { source, .. } => {
                use futures::io::ErrorKind::*;
                match source.kind() {
                    ConnectionReset | NetworkUnreachable | ConnectionAborted | NetworkDown
                    | BrokenPipe => true,
                    _ => false,
                }
            }
            QuinnConnection { source, .. } => {
                use quinn::ConnectionError::*;
                match source {
                    Reset | TimedOut => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}
