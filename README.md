# HTTP Redirector

HTTP Redirector provides a local HTTP redirect endpoint and an HTTP proxy. The HTTP endpoint redirects selected requests to HTTPS. The proxy forwards HTTP requests, upgrades selected upstream requests to HTTPS, and tunnels HTTPS `CONNECT` traffic.

Both listeners bind to `127.0.0.1`. The default ports are `59080` for the redirect endpoint and `59123` for the proxy. Set either port to `0` to disable that listener.

## Build

Build Linux binaries without CGO:

```sh
make build-amd64
make build-arm64
```

The binaries are written to `bin/http-redirector-linux-amd64` and `bin/http-redirector-linux-arm64`. Run `make build` to build both architectures, or `make test` to run the Go tests.

## Run

```sh
./bin/http-redirector-linux-amd64 --config-path config.yaml
```

The configuration path defaults to `config.yaml`. The `CONFIG_PATH` environment variable can also set it.

Configure clients to use `http://127.0.0.1:59123` as their HTTP and HTTPS proxy. The separate redirect endpoint listens on `http://127.0.0.1:59080`.

## Configuration

```yaml
log-level: info
log-source: false
log-json: true

# Set either port to 0 to disable its listener.
http-port: 59080
proxy-port: 59123

# An empty redirect list matches every host. Add rules to select hosts explicitly.
redirect-list:
  - "+.example.com"
  - "*.internal.example.com"
  - ".service.example.net"
  - "10.20.0.0/16"

# If omitted, the default bypass list is used. An explicit [] disables those defaults.
bypass-list:
  - "+.lan"
  - "localhost"
  - "192.168.0.0/16"
```

Domain rules are case-insensitive:

- `*.example.com` matches exactly one label before `example.com`, such as `www.example.com`.
- `+.example.com` matches the root domain and any number of subdomain labels.
- `.example.com` matches subdomains at any depth, but not the root domain.
- `xbox.*.example.com` matches exactly one label in the `*` position.
- CIDR entries match IP addresses.

Quote wildcard rules in YAML so characters such as `*` are parsed as string values.

Both the HTTP listener and proxy forward requests to the upstream. When a host matches `redirect-list` and does not match `bypass-list`, an HTTP request is bridged over HTTPS upstream while the client continues to use HTTP. Other requests use the scheme requested by the client. `CONNECT` requests to port 443 remain raw tunnels. A matching `CONNECT` request to port 80 establishes TLS to upstream port 443 and carries the client's plaintext HTTP through that TLS connection.

The default bypass list contains private, link-local, and selected multicast IPv4/IPv6 ranges, plus `.lan`, `.local`, and `.internal` suffix rules.
