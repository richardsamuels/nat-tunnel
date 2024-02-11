pub mod config;

pub mod client;
pub mod server;
pub mod tunnel;

pub mod net;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

mod string;
