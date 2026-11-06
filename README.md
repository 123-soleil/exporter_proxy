# exporter_proxy

> **Status: under development.** Nothing is implemented yet; this document
> describes the intended design and may change before the first release.

A small reverse proxy that puts **TLS, mutual TLS (mTLS) and/or HTTP basic
authentication** in front of Prometheus exporters that do not support them
natively (or where configuring each exporter separately is impractical).

A single `exporter_proxy` process serves **several listeners**. Each listener
has its own address, its own authentication settings and one or more routes
forwarding a path to an upstream exporter.

```
scraper --mTLS-->  :9100  /metrics           --> http://127.0.0.1:19100/metrics  (node_exporter)
scraper --basic--> :9443  /node/metrics      --> http://127.0.0.1:19100/metrics  (node_exporter)
                          /postgres/metrics  --> http://127.0.0.1:19187/metrics  (postgres_exporter)
```

## Goals

- Secure exporters without touching them: they listen on `127.0.0.1` only and
  the proxy is the single entry point exposed on the network.
- Several independent configurations in one process: one listener per
  exporter, several exporters behind one listener, or a mix of both.
- Reuse the standard Prometheus
  [web configuration format](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md)
  (via `prometheus/exporter-toolkit`) for TLS, client certificate verification
  and bcrypt-hashed basic auth users, instead of a custom format.
- Run unattended under a hardened systemd unit, as a static Go binary
  (`CGO_ENABLED=0`).
- Structured JSON logs (one event per line) and Prometheus metrics about the
  proxy itself.

## Design

### Listeners and routes

- A **listener** binds one address (`listen`) and references one web
  configuration file (`web_config_file`).
- A listener holds one or more **routes**. A route maps an exact request path
  to an upstream URL. Only `GET` requests are forwarded.
- Authentication is **per listener**: all routes of a listener share the same
  TLS/mTLS/basic auth settings. Routes needing different authentication must
  go on different listeners.
- Request credentials (`Authorization` header) are never forwarded upstream.

### Authentication modes

All modes are expressed in the web configuration file of the listener:

| Mode               | Web configuration content                                         |
|--------------------|-------------------------------------------------------------------|
| TLS only           | `tls_server_config.cert_file` + `key_file`                        |
| mTLS               | TLS + `client_ca_file` + `client_auth_type: RequireAndVerifyClientCert` |
| Basic auth         | `basic_auth_users` (bcrypt hashes); should be combined with TLS   |
| mTLS + basic auth  | both of the above                                                 |

### Proxy metrics

`exporter_proxy` exposes its own metrics on a dedicated listener (`/metrics`),
protected by its own web configuration file. It is a long-running daemon with
per-route counters, so an HTTP endpoint is used rather than the node_exporter
textfile collector. Planned metrics (names may change):

- `exporter_proxy_requests_total{listener,route,code}`
- `exporter_proxy_upstream_errors_total{listener,route}`
- `exporter_proxy_request_duration_seconds{listener,route}`

Labels only take values from the configuration (listener and route names),
never client addresses or user names, to keep cardinality low.

## Configuration

Main file (default `/etc/exporter_proxy/config.yml`, draft format):

```yaml
# Endpoint exposing exporter_proxy's own metrics.
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/exporter_proxy/web-metrics.yml

listeners:
  - name: node                 # used as metric label, must be unique
    listen: ":9100"
    web_config_file: /etc/exporter_proxy/web-mtls.yml
    routes:
      - path: /metrics
        upstream: http://127.0.0.1:19100/metrics

  - name: shared
    listen: ":9443"
    web_config_file: /etc/exporter_proxy/web-basic.yml
    routes:
      - path: /node/metrics
        upstream: http://127.0.0.1:19100/metrics
      - path: /postgres/metrics
        upstream: http://127.0.0.1:19187/metrics
```

Example mTLS web configuration (`web-mtls.yml`):

```yaml
tls_server_config:
  cert_file: /etc/exporter_proxy/tls/CHANGE_ME.crt
  key_file: /etc/exporter_proxy/tls/CHANGE_ME.key
  client_ca_file: /etc/exporter_proxy/tls/CHANGE_ME-ca.crt
  client_auth_type: RequireAndVerifyClientCert
```

Example basic auth web configuration (`web-basic.yml`):

```yaml
tls_server_config:
  cert_file: /etc/exporter_proxy/tls/CHANGE_ME.crt
  key_file: /etc/exporter_proxy/tls/CHANGE_ME.key
basic_auth_users:
  # bcrypt hash, generate with: htpasswd -nBC 12 "" | tr -d ':\n'
  prometheus: CHANGE_ME
```

Web configuration files contain private key paths and password hashes: keep
them owned by the service user with mode `0600`.

## Installation

Until the first stable release, `exporter_proxy` is built from source. Build
and install instructions will be added together with the `Makefile` and the
systemd deployment files.

Upstream exporters must be reconfigured to listen on `127.0.0.1` only;
otherwise their port remains reachable without authentication and the proxy
can be bypassed.

## Usage

Planned command line:

```sh
exporter_proxy --config /etc/exporter_proxy/config.yml
```

The process will run in the foreground, log JSON to stdout/stderr, exit with
a non-zero code on invalid configuration, and shut down gracefully on
`SIGTERM`.

## Development

Planned `Makefile` targets: `help` (default), `build`, `test`, `lint`, `clean`.

## License

[Apache License 2.0](LICENSE).

## References

- [Prometheus exporter-toolkit web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
