# nat-tunnel

A toy/educational project to allow access to internal TCP network services without
opening NAT ports or using a VPN. Similar to Cloudflare Access or [frp](https://github.com/fatedier/frp)
 but absolutely not production ready.

TLS support is provided by rustls when the `crypto` section of the config files
is filled out. Certificates must be in PEM format, while the key files must
be RSA keys in OpenSSL's tradional format. Conversion can be achieved with
the following command `openssl rsa -in key -out key.traditional -traditional`.

# Build/Dev/Run
```shell
cargo build
cargo clippy --no-deps
cargo test
# run these from the manifest directory or provide a path to configuration files
# e.g.: `-- -c path/to/cfg.toml`
cargo run --bin sts
cargo run --bin stc
```

# Config

*Warning* the default protocol is quic, which means you must provide a TLS cert
and key. If you want to try it out without TLS, add field `transport = "tcp"`
to both config files

## Client
```toml
# pre-shared key that should match between Client/Server. Max of 512 bytes
# Hint: generate this with LC_ALL=C tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' </dev/urandom | head -c 512; echo
psk = "abcd"
# the FQDN/IP of the Server and its port
addr = "127.0.0.1:12345"
# protocol = "quic" # Protocol subject to change w/o notice. Quic support is default and experimental

[crypto]
ca = "ca.pem"

# Each tunnel looks like this. Copy and paste more blocks to have more tunnels
[[tunnels]]
# The port to open on the Server. Must be unique for each Server
remote_port = 6000

# optional param to specify the hostname/ip of the Internal service
# local_hostname = "127.0.0.1" # defaults to 127.0.0.1

# When a connection to the Server on remote_port is opened, data will be
# redirected to this port on the client
local_port = 8000
```

## Server
```toml
# pre-shared key that should match between Client/Server. Max of 512 bytes
psk = "abcd"
# the address/port the Server should listen on
addr = "0.0.0.0:12345"
# protocol = "quic" # Must be same as client

[crypto]
key = "key.pem"
cert = "cert.pem"
```

The above configuration files will
1. Have the Server listen for clients on 12345
2. Have the Client connect to a server at 127.0.0.1:12345 with TLS
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
4. Data is shuffled:
    1. by the Client between the Internal and the Server
    2. by the Server between the External and the Client 
5. When either an External or Internal kills the connection, the Client/Server
does the same

# TODO
* Make sure we're not leaking handlers
* Less sloppy error handling
* More testing
* Optimize network packets/buffers
* Limit active number of connections
* Profile and monitor memory consumption
