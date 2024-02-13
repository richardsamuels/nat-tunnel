pub mod config;
pub mod net;

mod string;

pub mod client;
pub mod server;
pub mod redirector;

pub(crate) type StdResult<T, U> = std::result::Result<T, U>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = StdResult<T, net::Error>;

