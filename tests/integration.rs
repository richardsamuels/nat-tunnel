use httptest::{matchers::*, responders::*, Expectation, Server};
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Child;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.0.kill() {
            Err(e) => println!("Could not kill child process: {}", e),
            Ok(_) => println!("Successfully killed child process"),
        }
    }
}
impl AsRef<Child> for ChildGuard {
    fn as_ref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

async fn setup(
    addr: &SocketAddr,
    transport: &str,
    skip_tls: bool,
    self_signed: bool,
) -> (PathBuf, PathBuf) {
    let mut stc_cfg = format!(
        "
psk = \"abcd\"
addr = \"127.0.0.1:12000\"
transport = \"{transport}\"


[[tunnels]]
remote_port = 10000
local_port = {}
",
        addr.port()
    );

    if !skip_tls {
        stc_cfg.push_str(
            "
[crypto]
",
        );
        if self_signed {
            stc_cfg.push_str(
                "
allow_self_signed = true
",
            );
        } else {
            stc_cfg.push_str(
                "
ca = \"tests/ca.pem\"
",
            );
        }
    }

    let mut sts_cfg = format!(
        "
psk = \"abcd\"
addr = \"127.0.0.1:12000\"
transport = \"{transport}\"
"
    );

    if !skip_tls {
        sts_cfg.push_str(
            "
[crypto]
key = \"tests/server.key.pem\"
cert = \"tests/server.crt.pem\"
",
        );
    }

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests");

    let mut stc_path = d.clone();
    stc_path.push("stc.integration.toml");
    let mut sts_path = d.clone();
    sts_path.push("sts.integration.toml");

    {
        let mut stc_f = File::create(&stc_path).unwrap();
        let _ = stc_f.write_all(stc_cfg.as_bytes());

        let mut sts_f = File::create(&sts_path).unwrap();
        let _ = sts_f.write_all(sts_cfg.as_bytes());
    }

    (sts_path, stc_path)
}

static MTX: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn wait_for_server_udp(addr: &SocketAddr) {
    let mut tries = 5;
    loop {
        if tries == 0 {
            panic!(
                "Tried to connect, but failed. Did the server ever come up? {:?}",
                addr
            );
        }
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        if udp_socket.connect(addr).await.is_err() {
            sleep(Duration::from_millis(100)).await;
        } else {
            break;
        }
        tries -= 1
    }
}

async fn wait_for_server(addr: &SocketAddr) {
    let mut tries = 5;
    loop {
        if tries == 0 {
            panic!(
                "Tried to connect, but failed. Did the server ever come up? {:?}",
                addr
            );
        }
        let c = TcpStream::connect(addr).await;
        if c.is_err() {
            sleep(Duration::from_millis(100)).await;
        } else {
            break;
        }
        tries -= 1
    }
}

async fn start_(
    addr: &SocketAddr,
    protocol: &str,
    allow_insecure: bool,
    allow_self_signed: bool,
) -> (ChildGuard, ChildGuard) {
    let (sts_path, stc_path) = setup(addr, protocol, allow_insecure, allow_self_signed).await;

    let mut sts = test_bin::get_test_bin("sts");
    let sts_b = sts
        .arg("-c")
        .arg(sts_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    if allow_insecure {
        sts_b.arg("--allow-insecure-transport");
    }

    let sts_h = ChildGuard(sts_b.spawn().unwrap());

    // wait until we can connect to the server
    let addr = "127.0.0.1:12000".parse().unwrap();
    if protocol == "quic" {
        wait_for_server_udp(&addr).await;
    } else {
        wait_for_server(&addr).await;
    }

    let mut stc = test_bin::get_test_bin("stc");
    let stc_b = stc
        .arg("-c")
        .arg(stc_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if allow_insecure {
        stc_b.arg("--allow-insecure-transport");
    }
    let stc_h = ChildGuard(stc_b.spawn().unwrap());

    (sts_h, stc_h)
}

// XXX Hey, if it's 2026 or later and these tests are failing, it's because the
// certificate in the tests folder has expired
#[tokio::test]
async fn integration() {
    let _guard = MTX.lock();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/")).respond_with(status_code(200)),
    );

    let addr = server.addr();
    let (mut sts_h, mut stc_h) = start_(&addr, "tcp", false, false).await;

    let url = server.url("/");
    let resp = reqwest::get(url.to_string()).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    match sts_h.try_wait() {
        Ok(None) => (),
        _ => panic!("sts dead"),
    };

    match stc_h.try_wait() {
        Ok(None) => (),
        _ => panic!("stc dead"),
    };
}

#[tokio::test]
async fn integration_quic() {
    let _guard = MTX.lock();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/")).respond_with(status_code(200)),
    );

    let addr = server.addr();

    let (mut sts_h, mut stc_h) = start_(&addr, "quic", false, false).await;

    let url = server.url("/");
    let resp = reqwest::get(url.to_string()).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    match sts_h.try_wait() {
        Ok(None) => (),
        _ => panic!("sts dead"),
    };

    match stc_h.try_wait() {
        Ok(None) => (),
        _ => panic!("stc dead"),
    };
}

#[tokio::test]
async fn integration_quic_selfsigned() {
    let _guard = MTX.lock();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/")).respond_with(status_code(200)),
    );

    let addr = server.addr();

    let (mut sts_h, mut stc_h) = start_(&addr, "quic", false, true).await;

    let url = server.url("/");
    let resp = reqwest::get(url.to_string()).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    match sts_h.try_wait() {
        Ok(None) => (),
        _ => panic!("sts dead"),
    };

    match stc_h.try_wait() {
        Ok(None) => (),
        _ => panic!("stc dead"),
    };
}

#[tokio::test]
async fn integration_no_tls() {
    let _guard = MTX.lock();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/")).respond_with(status_code(200)),
    );

    let addr = server.addr();
    let (mut sts_h, mut stc_h) = start_(&addr, "tcp", true, false).await;

    let url = server.url("/");
    let resp = reqwest::get(url.to_string()).await.unwrap();

    assert!(resp.status().is_success());

    match sts_h.try_wait() {
        Ok(None) => (),
        _ => panic!("sts dead"),
    };

    match stc_h.try_wait() {
        Ok(None) => (),
        _ => panic!("stc dead"),
    };
}

#[tokio::test]
async fn integration_client_failure() {
    let _guard = MTX.lock();
    // Client failure MUST NOT crash server
    let addr: SocketAddr = "127.0.0.1:20000".parse().unwrap();

    let (mut sts_h, mut stc_h) = start_(&addr, "tcp", false, false).await;

    stc_h.kill().unwrap();
    let _ = stc_h.wait().unwrap();

    match sts_h.try_wait() {
        Ok(None) => (), // still running
        _ => panic!("sts dead"),
    };
}

#[tokio::test]
async fn integration_server_failure() {
    let _guard = MTX.lock();
    // Server failure MUST trigger client shutdown
    let addr: SocketAddr = "127.0.0.1:20000".parse().unwrap();

    let (mut sts_h, mut stc_h) = start_(&addr, "tcp", false, false).await;

    sts_h.kill().unwrap();
    let _ = stc_h.wait();

    match stc_h.try_wait() {
        Ok(Some(_)) => (),
        _ => panic!("stc still alive"),
    };
}
