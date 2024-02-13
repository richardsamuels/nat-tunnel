use httptest::{matchers::*, responders::*, Expectation, Server};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Child;

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

#[tokio::test]
async fn integration() {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/")).respond_with(status_code(200)),
    );

    let addr = server.addr();

    let stc_cfg = format!(
        "
psk = \"abcd\"
addr = \"127.0.0.1\"
port = 12000

[[tunnels]]
remote_port = 10000
local_port = {}
",
        addr.port()
    );

    let sts_cfg = "
psk = \"abcd\"
port = 12000
"
    .to_string();
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

    let mut sts = test_bin::get_test_bin("sts");
    let mut sts_h = ChildGuard(sts.arg("-c").arg(&sts_path).spawn().unwrap());

    let mut stc = test_bin::get_test_bin("stc");
    let mut stc_h = ChildGuard(stc.arg("-c").arg(&stc_path).spawn().unwrap());

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
