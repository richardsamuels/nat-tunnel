pub mod config;
pub mod net;
pub mod tls_self_signed;

pub mod client;
pub mod race;
pub mod redirector;
pub mod server;

//pub(crate) type StdResult<T, U> = std::result::Result<T, U>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = color_eyre::eyre::Result<T>;
