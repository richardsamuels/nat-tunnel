use simple_tunnel::net::frame::Datagram;
use simple_tunnel::redirector::PROTOCOL_OVERHEAD;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[test]
fn check_mtu() {
    // Default MTU is 1500 bytes. Calculate the size of the worst-case
    // overhead, i.e. a Datagram w/ an ipv6 address and verify the
    // PROTOCOL_OVERHEAD is set correctly
    let d = Datagram {
        id: SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080),
        port: 65000,
        data: vec![0, 1, 2],
    };
    let serialized = rmp_serde::to_vec(&d).unwrap();

    // 4 bytes for LengthDelimitedCodec's u32, but we remove the length of the
    // data vector
    let overhead_length = serialized.len() + 4 - d.data.len();

    assert_eq!(PROTOCOL_OVERHEAD, overhead_length);
}
