#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("connection has died")]
    ConnectionDead,
    #[error("connection refused")]
    ConnectionRefused,
    #[error("{0}")]
    Io(std::io::Error),
    #[error("{0}")]
    MsgPackDecode(rmp_serde::decode::Error),
    #[error("{0}")]
    MsgPackEncode(rmp_serde::encode::Error),
    #[error("received unexpected frame")]
    UnexpectedFrame,
    #[error("{0}")]
    Other(String),
}

impl<T> std::convert::From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(value: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::Other(value.to_string())
    }
}

impl std::convert::From<std::string::String> for Error {
    fn from(value: std::string::String) -> Self {
        Error::Other(value)
    }
}

impl std::convert::From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::Other(value.to_string())
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
