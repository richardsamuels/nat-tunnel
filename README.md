# simple-tunnel

A toy/educational project to allow access to internal network services without
opening NAT ports or using a VPN. Similar to Cloudflare Access or [frp](https://github.com/fatedier/frp)
 but absolutely not production ready.

# Architecture
## Nomenclature
* Remote: a publicly facing server (always 1)
* Client: a server in a private network, such as behind a NAT.
* B: an internal service that will be proxied by simply-tunnel
* A: an external requestor that is trying to access B through simple-tunnel

## How it works
1. A remote is started
2. One or more clients connects to the remote and pushes `crate::config::Tunnel`s
to the remote.
3. The remote listens on `remote_port`
4. An A connects to `remote_port`
5. Remote creates a listener on a randomly selected port.
6. Remote sends a message to the client asking it to connect to the port
mentioned on step 5
7. Client connects to the port created in step 5 and the B.
8. Remote reads from A and writes to Client (and vice versa) on the port
created in step 5. Client reads from remote and writes to B (and vice versa).
