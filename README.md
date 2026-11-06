# exporter_proxy

> **Status: under development.** Nothing is implemented yet; this document
> describes the intended design and may change before the first release.

A small reverse proxy that puts **TLS, mutual TLS (mTLS) and/or HTTP basic
authentication** in front of Prometheus exporters that do not support them
natively (or where configuring each exporter separately is impractical).

A single `exporter_proxy` process serves **several listeners**. Each listener
has its own address, its own authentication settings and one or more routes.
A route serves metrics from one source:

- an HTTP exporter over TCP (`http://127.0.0.1:19100/metrics`);
- an HTTP exporter over a Unix domain socket (UDS);
- a static file in the Prometheus text exposition format (`.prom`).

```
scraper --mTLS-->  :9100  /metrics           --> http://127.0.0.1:19100/metrics  (node_exporter)
scraper --basic--> :9443  /node/metrics      --> http://127.0.0.1:19100/metrics  (node_exporter)
                          /postgres/metrics  --> http://127.0.0.1:19187/metrics  (postgres_exporter)
                          /app/metrics       --> unix:/run/app/metrics.sock       (HTTP over UDS)
                          /batch/metrics     --> /var/lib/batch/metrics.prom      (static file)
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
- Classic exporter logs (`logfmt`, one event per line, no access log by
  default) and Prometheus metrics about the
  proxy itself.

## Design

### Listeners and routes

- A **listener** binds one address (`listen`) and references one web
  configuration file (`web_config_file`).
- A listener holds one or more **routes**. A route maps an exact request path
  to one source. Only `GET` (and `HEAD`) requests are accepted.
- Authentication is **per listener**: all routes of a listener share the same
  TLS/mTLS/basic auth settings. Routes needing different authentication must
  go on different listeners.
- Request credentials (`Authorization` header) are never forwarded upstream.

### HTTP responses

| Situation | Status | Notes |
|-----------|--------|-------|
| Content read and validated | `200` | Body returned unchanged, `Content-Type: text/plain; version=0.0.4; charset=utf-8`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. `HEAD` returns the headers only. |
| Path not configured on this listener | `404` | Matching is exact: `/metrics/` does not match `/metrics`. The query string is ignored for matching and never forwarded. |
| Method other than `GET` or `HEAD` | `405` | With `Allow: GET, HEAD`. |
| `max_concurrent_requests` reached | `503` | Immediate, never queued. |
| Source rejected | `502` | Body `source rejected: <reason>` with the reason only (`unavailable`, `timeout`, `too_large`, `stale`, `invalid`, `too_many_samples`); details such as paths or addresses only go to the logs, at `warn` level. |

`404` and `405` are answered before taking a concurrency slot: only real
source reads count against `max_concurrent_requests`. A request whose client
disconnects before the answer is not counted as a source failure.

### Route sources

Each route has exactly one source:

| Source         | Route keys                     | Behavior                                                                 |
|----------------|--------------------------------|--------------------------------------------------------------------------|
| HTTP over TCP  | `upstream`                     | Fetches the URL (`http://` only).                                        |
| HTTP over UDS (HTTP only, no raw stream) | `upstream` + `unix_socket` | Connects to the socket instead of the URL host; the URL path and query are sent as is (the host part is ignored, like `curl --unix-socket`). |
| Static file    | `file`                         | Reads the file on every request.                                         |

- `unix_socket` is only valid together with `upstream`; `file` excludes both.
- `file` and `unix_socket` must be absolute, clean paths: a relative path, a
  path containing `..`, `.` or duplicate slashes is rejected at startup, so
  the configuration never depends on the working directory and the target is
  exactly what is written.
- A `file` route requires `max_age` (no default): if the file's modification
  time is older than `max_age`, the scrape is rejected
  (`reason="stale"`), so a writer that stopped running cannot go unnoticed
  behind old values. Choose it as a few times the writer's period (for
  example `max_age: 15m` for a file written every 5 minutes).
- Upstream requests are sent with `Accept: text/plain;version=0.0.4` and a
  `User-Agent: exporter_proxy/<version>`; no client header is forwarded
  (`Authorization` in particular), redirects are not followed and any status
  other than `200` is a failure.
- The `HTTP_PROXY`/`HTTPS_PROXY` environment variables are ignored: scrapes
  always go straight to the configured upstream or socket.
- gzip-compressed responses are accepted; `max_body_bytes` applies to the
  decompressed size, so a small compressed body cannot expand without bound.
- Files are opened without blocking and checked on the open descriptor: a
  path pointing to a FIFO, a directory or a device fails immediately, and the
  file cannot be swapped between the checks and the read. Local reads cannot
  be interrupted, so for files `timeout` is checked once the read is done.
- Whatever the source, the content is validated before being served (see
  below). Any failure returns `502 Bad Gateway`, is logged and counted, so
  Prometheus marks the target down instead of scraping partial or unexpected
  data.
- Files must be written atomically (temporary file in the same directory,
  then rename) so that a half-written file is never served.

### Response validation and limits

Content validation is **mandatory and cannot be disabled**: the proxy only
ever serves data that parses as Prometheus metrics. This prevents a
misconfigured or compromised source (wrong file path, local admin page, error
page) from being exposed through the proxy.

- The whole response is read into memory, bounded by `max_body_bytes`, then
  parsed with the official Prometheus text parser
  ([`prometheus/common/expfmt`](https://pkg.go.dev/github.com/prometheus/common/expfmt)),
  not with regular expressions.
- Only the text exposition format (`version=0.0.4`) is accepted. Protobuf and
  OpenMetrics are not supported, so native histograms are not available
  through the proxy.
- The parser runs in UTF-8 mode, like Prometheus 3: classic names and quoted
  UTF-8 names (`{"my.metric", zone="a"} 1`) are both accepted.
- The format requires the last line to end with a newline: a body without
  it is rejected. An empty body (or comments only) is valid and has 0
  samples.
- Parse errors are logged with the line number and the kind of error only
  (e.g. `line 1: expected float as value`), never with the offending content:
  a misconfigured source pointing to sensitive data must not leak it into
  the logs.
- A response larger than `max_body_bytes` is rejected without being fully
  read (default 2 MiB). A source that does not answer within `timeout` is
  rejected (default 10 s). A response containing more than `max_samples`
  samples is rejected (default 24000; every line with a value counts, so each
  histogram bucket is one sample, like Prometheus' `sample_limit`). These three
  limits are set globally and can be lowered or raised per route.
- The validated body is returned unchanged with
  `Content-Type: text/plain; version=0.0.4; charset=utf-8`.
- Validation guarantees the format, not the harmlessness of the content:
  label values are still free text chosen by the source.
- Each listener serves at most `max_concurrent_requests` requests at the same
  time (default 2, set in `defaults` or per listener). Extra requests are answered immediately with
  `503 Service Unavailable` instead of queuing.
- Parsing is linear in the response size, but the parser allocates about
  **10 times the body size** while it runs. Peak memory is therefore bounded
  by roughly `11 × max_body_bytes ×` the sum of `max_concurrent_requests` over
  all listeners: with the defaults (2 MiB, 2 requests) and one listener,
  about 45 MiB in the worst case. The defaults fit common exporters; raise
  `max_body_bytes` (and `max_concurrent_requests`) only on the routes or
  listeners that need it (see `exporter_proxy_response_size_bytes`), and
  size `MemoryMax=` in the systemd unit accordingly.
- Parse cost is exposed as `exporter_proxy_parse_duration_seconds`.
  Reference measurements on synthetic node_exporter-like data (single
  parse on a laptop, Intel Core 7 150U, `go test -bench=Validate -benchmem
  ./internal/content/`):

  | Samples | Body size | Parse time | Allocated |
  |---------|-----------|------------|-----------|
  | 2,000   | ~130 KB   | ~5 ms      | ~1.4 MB   |
  | 10,000  | ~650 KB   | ~28 ms     | ~6.8 MB   |
  | 50,000  | ~3.3 MB   | ~90 ms     | ~34 MB    |
- The service user needs read access to the files and write access to the
  sockets (`connect()` on a Unix socket requires write permission on it),
  typically through group membership; the systemd unit and the AppArmor
  profile must allow these paths.

### Authentication modes

All modes are expressed in the web configuration file of the listener:

| Mode               | Web configuration content                                         |
|--------------------|-------------------------------------------------------------------|
| TLS only           | `tls_server_config.cert_file` + `key_file`                        |
| mTLS               | TLS + `client_ca_file` + `client_auth_type: RequireAndVerifyClientCert` |
| Basic auth         | `basic_auth_users` (bcrypt hashes); should be combined with TLS   |
| mTLS + basic auth  | both of the above                                                 |

Basic authentication without TLS sends the credentials in clear text on the
network. exporter_proxy still starts in that case, but logs a `warn` line for
each such listener at startup (`msg="basic authentication without TLS:
credentials travel in clear text"`), so that it shows up in log alerts.

### Proxy metrics

`exporter_proxy` exposes its own metrics on a dedicated listener, configured
in the `metrics` section (`listen`, which also accepts `systemd:<name>`, and
its own `web_config_file`, so it can use different credentials or
certificates than the proxied exporters). It serves `/metrics` only (other
paths get `404`) and is named `metrics` in logs, so no listener may use that
name. It is a long-running daemon with per-route counters, so an HTTP
endpoint is used rather than the node_exporter textfile collector.

Besides the standard `go_*`, `process_*` and
`promhttp_metric_handler_errors_total` metrics, it exports:

- `exporter_proxy_requests_total{listener,route,code}`: requests served;
  `route` is empty for paths that match no route (`404`).
- `exporter_proxy_request_duration_seconds{listener,route}` (histogram): total
  time to serve a request (fetch + parse), for matched routes only.
- `exporter_proxy_parse_duration_seconds{listener,route}` (histogram): time
  spent validating the content with the Prometheus parser.
- `exporter_proxy_response_size_bytes{listener,route}` (histogram): size of
  the content read from the source.
- `exporter_proxy_samples{listener,route}` (histogram): number of samples in
  the content read from the source.
- `exporter_proxy_source_errors_total{listener,route,reason}`: rejected
  scrapes, with `reason` in a fixed set: `unavailable` (connection, file or
  HTTP status error), `timeout`, `too_large`, `too_many_samples`, `invalid`
  (parse error), `stale` (file older than `max_age`).
- `exporter_proxy_file_modified_timestamp_seconds{listener,route}` (gauge):
  modification time of the file of each `file` route, updated on every scrape.
- `exporter_proxy_build_info{version,revision,branch,goversion,goos,goarch,tags}`
  (gauge, always 1): version of the running binary, from
  [`prometheus/common/version`](https://pkg.go.dev/github.com/prometheus/common/version),
  like other Prometheus exporters.
- `exporter_proxy_config_hash` (gauge): hash of the main configuration file
  as loaded, like Alertmanager's `alertmanager_config_hash`. It is the
  SHA-256 of the raw file bytes, truncated to its first 48 bits so that the
  value is exact in a float64. Comparing it across servers, or before and
  after a deployment, shows which configuration is actually running. Any byte
  change, comments included, changes the hash. Web configuration files are
  not included: exporter-toolkit re-reads them while running (see
  "Configuration reload"), so they are not part of the loaded state.
- `exporter_proxy_config_last_reload_successful` (gauge, 0 or 1): whether
  the last configuration load (startup or `SIGHUP`) succeeded.
- `exporter_proxy_config_last_reload_success_timestamp_seconds` (gauge): time
  of the last successful configuration load.
- `exporter_proxy_requests_in_flight{listener}` (gauge): requests holding a
  concurrency slot (reading a source).
- `exporter_proxy_requests_rejected_total{listener}`: requests refused with
  `503` because `max_concurrent_requests` was reached.

Labels only take values from the configuration (listener names and route
paths), from a fixed set (`reason`) or from HTTP status codes, never client
addresses, user names or requested paths, to keep cardinality low. The
series of every configured listener and route, including every `reason`, are
created at 0 at startup, so `rate()` and `increase()` alerts work from the
first scrape.

Example alerts:

```promql
# A source keeps failing.
increase(exporter_proxy_source_errors_total[15m]) > 0
# A metrics file stopped being updated (also caught by max_age).
time() - exporter_proxy_file_modified_timestamp_seconds > 3600
# Scrapes are refused: raise max_concurrent_requests or reduce scrapers.
increase(exporter_proxy_requests_rejected_total[15m]) > 0
# Configuration differs between servers that should be identical.
count(count_values("hash", exporter_proxy_config_hash)) > 1
```

## Configuration

Main file (default `/etc/exporter_proxy/config.yml`, option `--config`):

```yaml
# Endpoint exposing exporter_proxy's own metrics (required).
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/exporter_proxy/web-metrics.yml

# Optional. Replaces the built-in defaults for every route (and every listener
# for max_concurrent_requests); each value can still be overridden below.
defaults:
  timeout: 10s                  # maximum time to read a source
  max_body_bytes: 2097152       # 2 MiB, larger responses are rejected
  max_samples: 24000            # responses with more samples are rejected
  max_concurrent_requests: 2    # per listener, extra requests get 503

listeners:
  - name: node                 # used as metric label, must be unique
    listen: ":9100"
    web_config_file: /etc/exporter_proxy/web-mtls.yml
    max_concurrent_requests: 20   # per-listener override
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
        timeout: 20s                     # per-route override
      # HTTP exporter listening on a Unix domain socket.
      - path: /app/metrics
        upstream: http://localhost/metrics   # host ignored, path sent as is
        unix_socket: /run/app/metrics.sock
      # Static file in the Prometheus text exposition format.
      - path: /batch/metrics
        file: /var/lib/batch/metrics.prom
        max_age: 15m                     # required for file routes
```

### Parsing rules

- The file is decoded strictly: an unknown or misspelled key, at any level,
  is an error (exit code `1` at startup), never silently ignored.
- The file must contain exactly one YAML document; an empty file is an error.
- Durations use Go syntax with a unit (`500ms`, `10s`, `15m`, `1h`); a bare
  number such as `10` is rejected.
- Sizes are plain integers in bytes.

### Validation rules

After parsing, the configuration is validated. **All** problems are reported
together on one log line (each prefixed with its location, e.g.
`listener "shared" route "/metrics": ...`), and the process exits with code
`1`.

| Scope      | Rule |
|------------|------|
| `metrics`  | Required, with `listen` and `web_config_file`. |
| Listeners  | At least one. `name` required, unique, made of letters, digits, `_`, `.`, `-` (it is used as a metric label); `metrics` is reserved for the metrics endpoint. |
| `listen`   | Required, `host:port` with a port from 1 to 65535, or `systemd:<name>` (socket activation, see below); not shared with another listener or with `metrics`. |
| `web_config_file` | Required on every listener and on `metrics`. |
| Routes     | At least one per listener. |
| `path`     | Required, starts with `/`, clean (no `.`, `..`, `//` or trailing `/`), no `?` or `#`, unique within its listener (the same path may exist on another listener). |
| Source     | Exactly one: `upstream` or `file`. `unix_socket` only together with `upstream`. |
| `upstream` | `http://` only, with a host, without credentials (`user:password@`) or fragment. |
| Paths      | `file`, `unix_socket` and `web_config_file` are absolute and clean (`filepath.Clean` leaves them unchanged), so `/var/lib/../../etc/shadow` is rejected. |
| `max_age`  | Required on `file` routes, forbidden on other routes. |
| Limits     | `timeout`, `max_body_bytes`, `max_samples`, `max_concurrent_requests` and `max_age` must be greater than 0 wherever they are set. |

Once valid, the configuration is identified by a hash: the first 48 bits of
the SHA-256 of the file, logged as 12 hexadecimal digits at startup
(`msg="configuration loaded" ... hash=85c73f060656`) and exported later as
`exporter_proxy_config_hash`.

### Default values

Each limit is resolved in this order, the first one set wins:

1. the value on the route (`timeout`, `max_body_bytes`, `max_samples`) or on
   the listener (`max_concurrent_requests`);
2. the value in the `defaults` section;
3. the built-in default below.

| Key                       | Level            | Built-in default | Notes |
|---------------------------|------------------|------------------|-------|
| `timeout`                 | defaults, route  | `10s`            | Maximum time to fetch and read a source. |
| `max_body_bytes`          | defaults, route  | `2097152` (2 MiB)   | Larger responses are rejected (`too_large`). |
| `max_samples`             | defaults, route  | `24000`          | Responses with more samples are rejected (`too_many_samples`). |
| `max_concurrent_requests` | defaults, listener | `2`            | Extra requests get `503`. |
| `max_age`                 | route (`file`)   | none, required   | Older files are rejected (`stale`). |

Other built-in defaults:

| Setting           | Default                           |
|-------------------|-----------------------------------|
| `--config`        | `/etc/exporter_proxy/config.yml`  |
| `--log.level`     | `info`                            |
| `--log.format`    | `logfmt`                          |
| `--log.access`    | off                               |

### systemd socket activation

A listener can take its socket from systemd instead of binding it: set
`listen: "systemd:<name>"`, where `<name>` is the `FileDescriptorName=` of a
socket unit. systemd opens the port, so exposing the proxy on a port below
1024 needs no capability in the service (`CAP_NET_BIND_SERVICE`), and the
service can keep `CapabilityBoundingSet=` empty.

```ini
# /etc/systemd/system/exporter_proxy-node.socket
[Socket]
ListenStream=443
FileDescriptorName=node
Service=exporter_proxy.service

[Install]
WantedBy=sockets.target
```

```yaml
listeners:
  - name: node
    listen: "systemd:node"
    web_config_file: /etc/exporter_proxy/web-mtls.yml
    routes: ...
```

- Each `systemd:<name>` must match exactly one stream socket (one
  `ListenStream=` per socket unit). Startup fails if it is missing.
- Sockets passed by systemd but not used by any listener are closed, with a
  `warn` log line.
- Listeners using `systemd:` and listeners binding `host:port` can be mixed.
- The service unit must declare the socket units (`Sockets=` or
  `Requires=`/`After=`); ready-to-use files will be provided in `deploy/`.
- See
  [systemd.socket(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html)
  for `FileDescriptorName=`.

### Web configuration examples

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

Command line:

```sh
exporter_proxy --config /etc/exporter_proxy/config.yml
exporter_proxy --version
```

| Flag        | Description                                                        |
|-------------|--------------------------------------------------------------------|
| `--config`  | Path to the configuration file (default `/etc/exporter_proxy/config.yml`). |
| `--check`   | *Not implemented yet.* Check the whole setup without starting anything, then exit (see below). |
| `--log.level` | Minimum log level: `debug`, `info`, `warn`, `error` (default `info`). |
| `--log.format` | Log format: `logfmt` or `json` (default `logfmt`).              |
| `--log.access` | Log one line per served request (default off).                  |
| `--version` | Print version, revision and Go version on one line, then exit 0.   |

The version is injected at build time (`-ldflags -X`) from the git tag; a
build outside a tag reports the output of `git describe --tags --dirty`.

The process runs in the foreground and logs to stderr. At startup it:

1. loads and validates the configuration;
2. validates every web configuration file (all problems reported at once);
3. binds **every** listener address before serving any: if one address
   cannot be bound (port in use, permission), the already bound ones are
   released and the process exits with code `1`, so a half-started proxy
   never runs;
4. serves all listeners.

On `SIGTERM` (`systemctl stop`) or `SIGINT`, it stops accepting connections,
waits up to 15 seconds for in-flight requests to complete, closes the
remaining connections and exits with code `0` (`1` if connections had to be
closed or if a listener failed while running).

HTTP server limits: 10 s to receive the request (headers included), write
deadline of the longest route `timeout` plus 10 s, 60 s keep-alive idle
timeout, 16 KiB of request headers.

### Logs

Logs use the same format and flags as the other Prometheus exporters
([`prometheus/common/promslog`](https://pkg.go.dev/github.com/prometheus/common/promslog)):
one event per line, in `logfmt` by default, for example:

```
time=2026-11-06T14:00:00.000Z level=WARN source=handler.go:42 msg="source rejected" listener=shared route=/postgres/metrics reason=timeout duration_ms=10001
```

`--log.format=json` switches to one JSON object per line with the same fields,
for log pipelines that prefer JSON.

- No access log by default: a successful scrape logs nothing. Failures
  (rejected sources, refused requests, reload results) are always logged at
  `warn` or `error`.
- `--log.access` adds one `info` line per request (listener, route, status
  code, duration, size, client address), useful for debugging but noisy at
  normal scrape rates.
- Context is always in separate fields, never concatenated into `msg`. No
  colors are used.

### Checking a setup (`--check`)

`--check` goes further than validating the configuration syntax. It reports
every problem found (one log line each, not only the first one) and
exits with `0` if everything is correct, `1` otherwise:

- the main configuration is parsed and validated (same rules as at startup);
- each web configuration file exists, is readable and valid, and the
  certificate, key and client CA files it references are readable and can be
  loaded;
- each `file` route: the file exists, is a regular file, is readable and is
  not older than `max_age`;
- each `unix_socket` route: the path exists, is a socket and is writable
  (required by `connect()`).

Permissions depend on the user running the check: run it as the service user
to get a meaningful result:

```sh
sudo -u exporter_proxy exporter_proxy --check --config /etc/exporter_proxy/config.yml
```

`--check` does not contact HTTP upstreams over TCP. It is not used as
`ExecStartPre=` in the systemd unit, because a source that is temporarily
missing (exporter not started yet, file not written yet) must not prevent
the proxy from starting: at runtime such a source only makes its own route
answer `502`.

### Configuration reload (`SIGHUP`)

On `SIGHUP` (`systemctl reload exporter_proxy`), the configuration is read
and validated again:

- if it is invalid, the error is logged, the running configuration is kept
  and `exporter_proxy_config_last_reload_successful` is set to `0`;
- if it is valid, routes and limits are swapped atomically; listeners that
  were added are started, listeners that were removed or whose address or web
  configuration file changed are stopped gracefully (in-flight requests are
  completed) and restarted; `exporter_proxy_config_hash` is updated.

Web configuration files themselves do not need a reload, exporter-toolkit
re-reads them while running:

- `basic_auth_users` and `http_server_config.headers` on every request: a
  user added, removed or with a new password takes effect immediately;
- TLS settings (certificate, key, client CA) on every new connection, so a
  renewed certificate is picked up without restart.

Whether a listener uses TLS at all is decided at startup: adding or removing
`tls_server_config` requires a restart. Replace these files atomically
(write a temporary file, then rename it) so that a half-written file is
never read.

## Development

Requirements: Go 1.26 or later (required by `prometheus/common`), git, make,
and [golangci-lint](https://golangci-lint.run/) v2 for `make lint`.

| Target       | Description                                                       |
|--------------|-------------------------------------------------------------------|
| `make help`  | List targets (default target).                                    |
| `make build` | Build a static binary (`CGO_ENABLED=0`, `-trimpath`) into `bin/exporter_proxy`. |
| `make test`  | Run the unit tests.                                               |
| `make lint`  | Check `gofmt`, run `go vet` and `golangci-lint run`.              |
| `make clean` | Remove `bin/exporter_proxy` and coverage files (other files in `bin/`, such as tools, are kept). |

`make lint` uses `bin/golangci-lint` when that file exists, otherwise
`golangci-lint` from `PATH`; `make lint GOLANGCI_LINT=/path/to/golangci-lint`
forces another one.

`make build` injects version information with `-ldflags -X` into
`prometheus/common/version`: `VERSION` (default `git describe --tags --dirty
--always`), `REVISION`, `BRANCH` and `BUILD_DATE` (date of the last commit, in
UTC, so rebuilding a commit gives the same values). Each can be overridden,
e.g. `make build VERSION=1.0.0`.

Tests must not be run from a `noexec` mount: `go test` executes the test
binaries it builds in `$TMPDIR`. On a server where `/tmp` is `noexec`, point
`GOTMPDIR` to an executable directory.

## License

[Apache License 2.0](LICENSE).

## References

- [Prometheus exporter-toolkit web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
