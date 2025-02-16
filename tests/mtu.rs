use nat_tunnel::net::Datagram;
use nat_tunnel::redirector::PROTOCOL_OVERHEAD;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[test]
fn check_mtu() {
    // Calculate the size of the worst-case overhead, i.e. a
    // Datagram w/ an ipv6 address and verify the const
    // PROTOCOL_OVERHEAD is set correctly
    let ipv6_addr = Ipv6Addr::new(
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    );

    let d = Datagram {
        id: SocketAddr::new(IpAddr::V6(ipv6_addr), 65000),
        port: 65000,
        data: vec![0, 1, 2],
    };
    let serialized = rmp_serde::to_vec(&d).unwrap();

    // 4 bytes for LengthDelimitedCodec's u32, but we remove the length of the
    // data vector
    let overhead_length = serialized.len() + 4 - d.data.len();

    assert_eq!(PROTOCOL_OVERHEAD as usize, overhead_length);
}
