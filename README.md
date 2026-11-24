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

# Matching requests are rejected unless redirect-list also matches.
deny-list:
  - "+.blocked.example"
  - "203.0.113.0/24"
  - "!safe.blocked.example"

# If omitted, the default bypass list is used. An explicit [] disables those defaults.
bypass-list:
  - "+.lan"
  - "localhost"
  - "192.168.0.0/16"
```

Domain rules are case-insensitive:

- `*.example.com` matches exactly one label before `example.com`, such as `www.example.com`.
- `+` matches every valid domain. `*` continues to match only a single-label domain such as `localhost`.
- `+.example.com` matches the root domain and any number of subdomain labels.
- `.example.com` matches subdomains at any depth, but not the root domain.
- `xbox.*.example.com` matches exactly one label in the `*` position.
- Prefix a rule with `!` to exclude its matches from that rule list. Exclusions override positive rules in the same list. A list containing only exclusions matches everything except those exclusions within the same domain or IP matcher. Domain rules do not match IP addresses, and CIDRs do not match domains.
- CIDR entries match IP addresses.
- Domain rules use ASCII DNS labels, with a maximum total length of 253 characters, 63 characters per label, and 127 labels. Labels may contain letters, digits, and internal hyphens.

Quote wildcard rules in YAML so characters such as `*` are parsed as string values.

Rules are evaluated in this order. A `redirect-list` match upgrades HTTP traffic to HTTPS upstream, even when `deny-list` or `bypass-list` also matches. Otherwise, a `deny-list` match is rejected with HTTP 403. A `bypass-list` match forwards directly. Hosts matching neither redirect nor bypass are denied by default. An empty `redirect-list` matches every valid host, so use a non-empty list when deny or bypass rules should apply.

Both the HTTP listener and proxy forward requests to the upstream. Upgraded HTTP requests are bridged over HTTPS while the client continues to use HTTP. Other requests use the scheme requested by the client. `CONNECT` requests to port 443 remain raw tunnels. A matching `CONNECT` request to port 80 establishes TLS to upstream port 443 and carries the client's plaintext HTTP through that TLS connection.

The default bypass list contains private, link-local, and selected multicast IPv4/IPv6 ranges, plus `.lan`, `.local`, and `.internal` suffix rules.
