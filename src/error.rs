use snafu::prelude::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("network error: {source}"))]
    Net {
        #[snafu(backtrace)]
        source: crate::net::Error,
    },
    #[snafu(display("network error: {source}"))]
    ClientValidation {
        #[snafu(backtrace)]
        source: crate::server::ClientValidationError,
    },
    #[snafu(display("config error: {source}"))]
    Config {
        #[snafu(backtrace)]
        source: crate::config::Error,
    },
    #[snafu(display("join error: {source}"))]
    JoinError { source: tokio::task::JoinError },
}

impl From<tokio::task::JoinError> for Error {
    fn from(source: tokio::task::JoinError) -> Self {
        Error::JoinError { source }
    }
}

impl From<crate::config::Error> for Error {
    fn from(source: crate::config::Error) -> Self {
        Error::Config { source }
    }
}

impl From<crate::net::Error> for Error {
    fn from(source: crate::net::Error) -> Self {
        Error::Net { source }
    }
}

impl From<crate::server::ClientValidationError> for Error {
    fn from(source: crate::server::ClientValidationError) -> Self {
        Error::ClientValidation { source }
    }
}
