pub mod config;

pub mod client;
pub mod remote;

pub mod net;

pub mod redirector;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

mod string;
pub use crate::string::LimitedString;
