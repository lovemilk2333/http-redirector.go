# HTTP Redirector

HTTP Redirector provides a local HTTP endpoint and an HTTP proxy. Both route requests using domain and CIDR rules, upgrade selected HTTP requests to HTTPS upstream, and tunnel HTTPS `CONNECT` traffic.

Both listeners bind to `127.0.0.1`. The default ports are `59080` for the redirect endpoint and `59123` for the proxy. Set either port to `0` to disable that listener.

## Build

Build Linux binaries without CGO:

```sh
make build-amd64
make build-arm64
```

The binaries are written to `bin/linux-amd64/http-redirector` and `bin/linux-arm64/http-redirector`. Run `make build` to build both architectures, or `make test` to run the Go tests.

## Run

```sh
./bin/linux-amd64/http-redirector --config-path config.yaml
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

# Each rule is a domain or CIDR, a semicolon, and an action.
rules:
  - "+.example.com;redirect"
  - "*.internal.example.com;redirect"
  - ".service.example.net;redirect"
  - "10.20.0.0/16;redirect"
  - "+.blocked.example;deny"
  - "203.0.113.0/24;deny"
  - "!safe.blocked.example;deny"
  - "+.lan;bypass"
  - "localhost;bypass"
  - "192.168.0.0/16;bypass"
```

When `rules` is omitted, the built-in private-network and local-domain rules are loaded with the `bypass` action. Set `rules: []` to remove them.

Domain rules are case-insensitive:

- `*.example.com` matches exactly one label before `example.com`, such as `www.example.com`.
- `+` matches every valid domain. `*` continues to match only a single-label domain such as `localhost`.
- `+.example.com` matches the root domain and any number of subdomain labels.
- `.example.com` matches subdomains at any depth, but not the root domain.
- `xbox.*.example.com` matches exactly one label in the `*` position.
- Each rule action is `redirect`, `bypass`, or `deny`. Rules are evaluated from top to bottom, and the first matching rule decides the route. Prefix a domain or CIDR with `!` to invert that rule's match condition. Domain rules only match domain names, and CIDRs only match IP addresses.
- CIDR entries match IP addresses.
- Domain rules use ASCII DNS labels, with a maximum total length of 253 characters, 63 characters per label, and 127 labels. Labels may contain letters, digits, and internal hyphens.

Quote wildcard rules in YAML so characters such as `*` are parsed as string values.

The first matching rule decides whether traffic is redirected, bypassed, or denied. An unmatched host is denied. A `bypass` match forwards using the requested scheme without upgrading HTTP to HTTPS. Put specific exceptions before broader rules, such as `safe.example.com;bypass` before `+.example.com;redirect`.

Both the HTTP listener and proxy forward requests to the upstream. Redirected HTTP requests are bridged over HTTPS while the client continues to use HTTP. Bypassed HTTP requests remain HTTP upstream. `CONNECT` requests to port 443 remain raw tunnels. A redirected `CONNECT` request to port 80 establishes TLS to upstream port 443 and carries the client's plaintext HTTP through that TLS connection. Debug logs include the selected destination for HTTP and CONNECT requests.

The default bypass list contains private, link-local, and selected multicast IPv4/IPv6 ranges, plus `.lan`, `.local`, and `.internal` suffix rules.
