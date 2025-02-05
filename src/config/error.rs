use snafu::prelude::*;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("{message}: {source}"))]
    Io {
        message: String,
        source: std::io::Error,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("toml decode error: {source}"))]
    Decode {
        #[snafu(source(from(toml::de::Error, Box::new)))]
        source: Box<toml::de::Error>,
    },
    #[snafu(display("duplicate tunnels: {tunnels:?}"))]
    DuplicateTunnels { tunnels: Vec<u16> },
    #[snafu(display("bad certificate: {source}"))]
    Certificate {
        source: rustls_pki_types::pem::Error,
    },
    #[snafu(display("invalid private key: {source}"))]
    InvalidKey {
        source: rustls_pki_types::pem::Error,
    },
    #[snafu(display("unsafe transport enabled without --allow-unsafe-transport"))]
    UnsafeTransport,
}

impl From<toml::de::Error> for Error {
    fn from(source: toml::de::Error) -> Self {
        // TODO why can't i use context/.build() here?

        Error::Decode {
            source: source.into(),
        }
    }
}
