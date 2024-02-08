use mio::net as mnet;
use simple_tunnel::{config, Result, client};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::mpsc;
use tracing::{error, info};

fn main2() -> Result<()> {
    let (sigint_tx, sigint_rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = sigint_tx.send(());
    })?;

    let c = config::load_client_config();

    loop {
        let addr: SocketAddr = format!("{}:{}", c.addr, c.port).parse().unwrap();
        info!("Handshaking with {}", &addr);
        let stream = mnet::TcpStream::connect(addr)?;
        let mut client = client::Client::new(stream)?;

        if let Err(e) = client.push_tunnel_config(&c) {
            panic!("connection to {} failed: {}", addr, e);
        };

        match client.run(&c, &sigint_rx) {
            Ok(_) => return Ok(()),
            Err(e) => {
                let s = e.to_string();
                if s == "Interrupted system call (os error 4)" {
                    return Ok(());
                } else if s == "connection dead" {
                    info!(cause = ?e, "Connection to remote appears dead. Retrying");
                    continue;
                }
                error!(cause = ?e, "client error");
            }
        }
    }
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
