use mio::net as mnet;
use simple_tunnel::Result;
use simple_tunnel::{config, remote};
use std::net::SocketAddr;
use std::process::ExitCode;
use tracing::{error, info};

fn main2() -> Result<u8> {
    let c = config::load_server_config();

    let addr: SocketAddr = format!("0.0.0.0:{}", c.port).parse().unwrap();
    info!("Listening on {}", &addr);
    let listener = mnet::TcpListener::bind(addr)?;

    let mut transport = remote::Remote::new(listener)?;
    loop {
        match transport.run(&c.psk) {
            Err(e) => return Err(e),
            Ok(()) => break,
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    ExitCode::from(match main2() {
        Ok(_) => 0,
        Err(e) => {
            error!(cause = e, "Exiting");
            1
        }
    })
}
