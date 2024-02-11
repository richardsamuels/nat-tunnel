

#[derive(Debug)]
pub enum Error {
    ConnectionDead,
    Io(std::io::Error),
    MsgPackDecode(rmp_serde::decode::Error),
    MsgPackEncode(rmp_serde::encode::Error),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::MsgPackEncode(e) => write!(f, "{}", e),
            Error::MsgPackDecode(e) => write!(f, "{}", e),
            Error::Other(s) => write!(f, "{}", s),
            Error::ConnectionDead => write!(f, "simple_tunnel::net::Error::ConnectionDead"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::MsgPackDecode(e) => Some(e),
            Error::MsgPackEncode(e) => Some(e),
            _ => None,
        }
    }
}

impl std::convert::From<std::string::String> for Error {
    fn from(value: std::string::String) -> Self {
        Error::Other(value)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
