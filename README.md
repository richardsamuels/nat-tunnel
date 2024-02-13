# simple-tunnel

A toy/educational project to allow access to internal TCP network services without
opening NAT ports or using a VPN. Similar to Cloudflare Access or [frp](https://github.com/fatedier/frp)
 but absolutely not production ready.

# Build/Dev/Run
```shell
cargo build
cargo clippy
cargo test
```

# Config

## Client
```toml
# pre-shared key that should match between Client/Server. Max of 512 bytes
psk = "abcd"
# the FQDN/IP of the Server
addr = "127.0.0.1"
# the port of the Server
port = 12345

# Each tunnel looks like this. Copy and paste more blocks to have more tunnels
[[tunnels]]
# The port to open on the Server. Must be unique for each Server
remote_port = 6000
# When a connection to the Server on remote_port is opened, data will be
# redirected to this port on the client
local_port = 8000
```

## Server
```toml
# pre-shared key that should match between Client/Server. Max of 512 bytes
psk = "abcd"
# the port the Sever should listen on
port = 12345
```

The above configuration files will
1. Have the Server listen for clients on 12345
2. Have the Client connect to a server at 127.0.0.1:12345
3. Have the Server open a listener on port 6000, which redirects all TCP
traffic to the socket 127.0.0.1:8000 on the Client

# Architecture
## Nomenclature
* Server : a publicly facing server (always 1 from the perpsective of a client)
* Client: a server in a private network, such as behind a VPN or (CG)NAT.
* Internal: an internal service that will be proxied by simply-tunnel
* External: an external requestor that is trying to access Internal through simple-tunnel

## How it works
### Server/Client Initialization
1. A Server is started
2. One or more Clients connects to the Server (socket is marked keepalive) and
pushes `crate::config::Tunnel`s to the Server.
3. The Server listens on each of the provided `remote_port`s

### When an External tries to connect:
1. An External connects to `remote_port`
2. Server reads and data and ships it over the network to the correct Client
3. Client takes the data and opens a connection to the correct Internal.
4a. Data is shuffled by the Client between the Internal to the Server
4b. Data is shuffled by the Server between the External and the Server
5. When either an External or Internal kills the connection, the Client/Server
does the same

# TODO
* TLS
* Optimize network packets for ethernet frame size
* Less sloppy error handling
