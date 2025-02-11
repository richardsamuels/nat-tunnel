#[cfg(not(unix))]
compile_error!("Integration tests require a Unix-like platform");

use httptest::{matchers::*, responders::*, Expectation, Server};
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Child;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

// std::process::Child is not killed on drop.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        match self.0.kill() {
            Err(e) => println!("Could not kill child process: {}", e),
            Ok(_) => println!("Successfully killed child process: {}", self.id()),
        }
    }
}
impl AsRef<Child> for ChildGuard {
    fn as_ref(&self) -> &Child {
        &self.0
    }
}
impl AsMut<Child> for ChildGuard {
    fn as_mut(&mut self) -> &mut Child {
        &mut self.0
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

fn sigint(child: &Child) {
    // SAFETY: Without importing a thousand more crates, this is the way
    // to send SIGINT. Obviously not cross compatible, but who cares about
    // Windows?
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
}

async fn setup(
    addr: &SocketAddr,
    server_port: u16,
    tunnel_port: u16,
    transport: &str,
    skip_tls: bool,
    self_signed: bool,
) -> (PathBuf, PathBuf) {
    let mut stc_cfg = format!(
        "
psk = \"abcd\"
addr = \"127.0.0.1:{server_port}\"
transport = \"{transport}\"


[[tunnels]]
remote_port = {tunnel_port}
local_hostname = \"::1\"
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
addr = \"127.0.0.1:{server_port}\"
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
            sleep(Duration::from_millis(25)).await;
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
    protocol: &str,
    allow_insecure: bool,
    allow_self_signed: bool,
) -> (ChildGuard, ChildGuard, httptest::Server, String) {
    let server = Server::run();
    let server_port = portpicker::pick_unused_port().expect("Failed to get random port");
    let tunnel_port = portpicker::pick_unused_port().expect("Failed to get random port");
    println!(
        "Test using server port: {server_port}, tunnel port: {tunnel_port}, inner: {server}",
        server = server.addr().port()
    );
    let (sts_path, stc_path) = setup(
        &server.addr(),
        server_port,
        tunnel_port,
        protocol,
        allow_insecure,
        allow_self_signed,
    )
    .await;

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

    let server_addr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    if protocol == "quic" {
        wait_for_server_udp(&server_addr).await;
    } else {
        wait_for_server(&server_addr).await;
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

    server.expect(
        Expectation::matching(request::method_path("GET", "/uptimewaiter"))
            .times(1..)
            .respond_with(status_code(200)),
    );

    let uptime_url = format!("http://127.0.0.1:{}/uptimewaiter", tunnel_port)
        .parse()
        .unwrap();

    let mut tries = 50;
    while tries > 0 {
        let g = get(&uptime_url).await;
        tries -= 1;
        if g.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }

        if g.unwrap().status().is_success() {
            break;
        }
    }
    if tries == 0 {
        panic!("Server never came up after 5 seconds");
    }

    let url = format!("http://127.0.0.1:{}/realpath", tunnel_port)
        .parse()
        .unwrap();

    (sts_h, stc_h, server, url)
}

async fn get(url: &String) -> std::result::Result<reqwest::Response, reqwest::Error> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    client.get(url).send().await
}

// XXX Hey, if it's 2026 or later and these tests are failing, it's because the
// certificate in the tests folder has expired. Use rcgen at that point
#[tokio::test]
async fn integration() {
    let _guard = MTX.lock();

    let (sts_h, stc_h, server, url) = start_("tcp", false, false).await;
    server.expect(
        Expectation::matching(request::method_path("GET", "/realpath"))
            .times(1)
            .respond_with(status_code(200)),
    );
    let resp = get(&url).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    shutdown(stc_h, sts_h)
}

#[tokio::test]
async fn integration_quic() {
    let _guard = MTX.lock();

    let (sts_h, stc_h, server, url) = start_("quic", false, false).await;
    server.expect(
        Expectation::matching(request::method_path("GET", "/realpath"))
            .respond_with(status_code(200)),
    );

    let resp = get(&url).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    shutdown(stc_h, sts_h)
}

#[tokio::test]
async fn integration_quic_selfsigned() {
    let _guard = MTX.lock();

    let (sts_h, stc_h, server, url) = start_("quic", false, true).await;
    server.expect(
        Expectation::matching(request::method_path("GET", "/realpath"))
            .respond_with(status_code(200)),
    );

    let resp = get(&url).await.unwrap();

    // assert the response has a 200 status code.
    assert!(resp.status().is_success());

    shutdown(stc_h, sts_h)
}

#[tokio::test]
async fn integration_no_tls() {
    let _guard = MTX.lock();

    let (sts_h, stc_h, server, url) = start_("tcp", true, false).await;
    server.expect(
        Expectation::matching(request::method_path("GET", "/realpath"))
            .times(1)
            .respond_with(status_code(200)),
    );

    let resp = get(&url).await.unwrap();

    assert!(resp.status().is_success());

    shutdown(stc_h, sts_h)
}

fn shutdown(mut stc_h: ChildGuard, mut sts_h: ChildGuard) {
    match sts_h.try_wait() {
        Ok(None) => (),
        _ => panic!("sts dead"),
    };

    match stc_h.try_wait() {
        Ok(None) => (),
        _ => panic!("stc dead"),
    };

    sigint(&stc_h);
    let stc_res = stc_h.wait();
    sigint(&sts_h);
    let sts_res = sts_h.wait();
    assert!(stc_res.unwrap().success());
    assert!(sts_res.unwrap().success());
}

#[tokio::test]
async fn integration_client_failure() {
    let _guard = MTX.lock();
    // Client failure MUST NOT crash server

    let (mut sts_h, mut stc_h, _, _) = start_("tcp", false, false).await;

    stc_h.kill().unwrap();
    let _ = stc_h.wait().unwrap();

    sigint(&sts_h);
    assert!(sts_h.wait().unwrap().success());
}

#[tokio::test]
async fn integration_client_failure_quic() {
    let _guard = MTX.lock();
    // Client failure MUST NOT crash server

    let (mut sts_h, mut stc_h, _, _) = start_("quic", false, true).await;

    stc_h.kill().unwrap();
    let _ = stc_h.wait().unwrap();

    sigint(&sts_h);
    assert!(sts_h.wait().unwrap().success());
}

#[tokio::test]
async fn integration_server_failure() {
    let _guard = MTX.lock();
    // Server failure MUST trigger client shutdown

    let (mut sts_h, mut stc_h, _, _) = start_("tcp", false, false).await;

    sts_h.kill().unwrap();
    let _ = stc_h.wait();

    match stc_h.try_wait() {
        Ok(Some(_)) => (),
        _ => panic!("stc still alive"),
    };
    sigint(&stc_h);
    assert_eq!(stc_h.wait().unwrap().code().unwrap(), 1);
}

#[tokio::test]
async fn integration_server_failure_quic() {
    let _guard = MTX.lock();
    // Server failure MUST trigger client shutdown

    let (mut sts_h, mut stc_h, _, _) = start_("quic", false, true).await;

    sts_h.kill().unwrap();
    let _ = stc_h.wait();

    match stc_h.try_wait() {
        Ok(Some(_)) => (),
        _ => panic!("stc still alive"),
    };
    sigint(&stc_h);
    assert_eq!(stc_h.wait().unwrap().code().unwrap(), 1);
}
