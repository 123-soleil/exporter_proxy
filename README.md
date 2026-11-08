# exporter_proxy

> **Status: 0.x.** Implemented and tested; the configuration and metrics
> may still change before 1.0.

A small reverse proxy that puts **TLS, mutual TLS (mTLS) and/or HTTP basic
authentication** in front of Prometheus exporters that do not support them
natively (or where configuring each exporter separately is impractical).

A single `exporter_proxy` process serves **several listeners**. Each listener
has its own address, its own authentication settings and one or more routes.
A route serves metrics from one source:

- an HTTP exporter over TCP (`http://127.0.0.1:19100/metrics`), or over
  HTTPS with optional mTLS for an exporter on another machine;
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
  for TLS, client certificate verification and bcrypt-hashed basic auth
  users, instead of a custom format. Files are validated and TLS settings
  built with `prometheus/exporter-toolkit`; authentication is enforced by
  exporter_proxy itself, so that every refusal is logged and counted.
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
  go on different listeners. Within a listener, a route can be restricted to
  some of its authenticated clients (`authorize`, see "Route authorization").
- Request credentials (`Authorization` header) are never forwarded upstream.

### HTTP responses

| Situation | Status | Notes |
|-----------|--------|-------|
| Content read and validated | `200` | Body returned unchanged (unless the route has a `metrics_filter`), `Content-Type: text/plain; version=0.0.4; charset=utf-8` (or the protobuf type, see "Formats"), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Vary: Accept, Accept-Encoding`. Compressed with gzip (`Content-Encoding: gzip`, fastest level) when the client accepts it (`Accept-Encoding`, as Prometheus sends) and the body is 1 KiB or more: the network hop between the scraper and the proxy carries about a tenth of the size. `HEAD` returns the headers only. |
| Authenticated, but not in the `authorize` list of the route | `403` | Counted as `forbidden` in `exporter_proxy_auth_failures_total`. |
| Path not configured on this listener | `404` | Matching is exact: `/metrics/` does not match `/metrics`. The query string is ignored for matching, and only forwarded as allowed by the route's `forward_params` (see "Forwarded query parameters"). |
| Query string refused by the route's `forward_params` | `400` | Body naming the problem (parameter not allowed, value not allowed, given twice, too long, required parameter missing); never echoes client values. |
| Method other than `GET` or `HEAD` | `405` | With `Allow: GET, HEAD`. |
| `max_concurrent_requests` reached (listener, or route when set) | `503` | Immediate, never queued. A request for a route whose source is already being read does not need a slot: it shares that read (see below), or starts its own if the running read was told a shorter timeout than its budget and a slot is free. On a route with `cache_ttl`, a fresh cached answer is served instead of `503`. |
| Web configuration file of the listener unreadable or invalid; without `basic_auth_users` while the listener requires basic authentication (started with it, or users seen while running); or enabling TLS while the listener serves plain HTTP | `518` | Body `web configuration unreadable`; answered to every request (after the `rate_limit` of the web configuration, if any, but before authentication) until the file is fixed (it is re-read on every request). The error goes to the logs at `error` level and `exporter_proxy_web_config_read_error{listener}` is set to 1. `518` is an unassigned code, chosen so that this case is never confused with an upstream (`502`) or proxy error. |
| Source rejected | `502` | Body `source rejected: <reason>` with the reason only (`unavailable`, `timeout`, `too_large`, `stale`, `invalid`, `too_many_samples`); details such as paths or addresses only go to the logs, at `warn` level. |

`OPTIONS *` goes through authentication like any request (no automatic
answer from net/http), then gets `404` (`400` on the metrics endpoint).

`404` and `405` are answered before taking a concurrency slot: only real
source reads count against `max_concurrent_requests`. A request whose client
disconnects before the answer is not counted as a source failure: it is
recorded with code `499` (nginx convention) in
`exporter_proxy_requests_total`, so that it does not count as a `5xx`, while
a `502` is still written in case the client is still reading.

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
  time is older than `max_age`, or more than `max_age` in the future (writer
  with a clock far ahead), the scrape is rejected
  (`reason="stale"`), so a writer that stopped running cannot go unnoticed
  behind old values. Choose it as a few times the writer's period (for
  example `max_age: 15m` for a file written every 5 minutes).
- Upstream requests are sent with `Accept: text/plain;version=0.0.4` (or
  the delimited protobuf format first, when the scraper prefers it: see
  "Formats"), a `User-Agent: exporter_proxy/<version>` and
  `X-Prometheus-Scrape-Timeout-Seconds`, computed by the proxy: the scrape
  budget of the request starting the read (derived from its scrape
  timeout, see "Response validation and limits"), or the route timeout without a scrape
  timeout header, whichever is shorter. A request does not join a read
  that told the upstream less than its own budget (another client's short
  timeout), unless no slot is left for a read of its own: it then shares
  the running read rather than being refused. Exporters such as
  blackbox_exporter and snmp_exporter use it to answer in time (a failed
  probe as `probe_success 0` rather than a failed scrape); no client header is forwarded
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

### Forwarded query parameters

Multi-target exporters (blackbox_exporter, snmp_exporter) take the target
in the query string (`/probe?target=…&module=…`). By default the proxy
ignores the query string. `forward_params` forwards some parameters,
each restricted to listed values or patterns:

```yaml
routes:
  - path: /probe
    upstream: http://127.0.0.1:9115/probe
    forward_params:
      target:
        values: [https://www.example.com]
        patterns: ['10\.0\.0\.[0-9]{1,3}:443']   # whole value, RE2 syntax
        required: true
      module:
        values: [http_2xx, tcp_connect]
```

- Only listed parameters are accepted, each once, with a value of at most
  1024 bytes that is one of `values` or matches one of `patterns` (anchored:
  the whole value must match). Anything else gets `400` and never reaches
  the upstream. A `required` parameter must be present.
- Restrict values as tightly as possible: an exporter probing any target
  it is given would let the clients of the route probe the internal
  network (and cloud metadata addresses) through it.
- Forwarded parameters are appended to the query of the `upstream` URL,
  which is kept as written and cannot be overridden: a parameter set in
  the URL cannot be listed, and that query must be plain `name=value`
  pairs joined by `&` (so that every name in it is seen).
- Each pattern must be a valid regular expression on its own: one closing
  the anchoring early (`a)|(.*`) is refused.
- Requests with different parameters never share a read.
- Routes with a `required` parameter are left out of `/sd` (service
  discovery): configure their targets in Prometheus, for example:

```yaml
scrape_configs:
  - job_name: blackbox
    metrics_path: /probe
    params: { module: [http_2xx] }
    static_configs:
      - targets: [https://www.example.com]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: node1.example.com:9443   # the proxy listener
```

### HTTPS upstreams

An exporter on another machine, or one serving TLS itself, is read over
`https://`. The upstream certificate is always verified: against the
system roots by default, or against `ca_file`. `cert_file` and `key_file`
add a client certificate, for an exporter requiring mTLS (an exporter-toolkit
web configuration with `client_auth_type`):

```yaml
routes:
  - path: /remote/metrics
    upstream: https://db1.internal:9187/metrics
    upstream_tls:
      ca_file: /etc/exporter_proxy/tls/exporters-ca.pem
      cert_file: /etc/exporter_proxy/tls/proxy-client.crt
      key_file: /etc/exporter_proxy/tls/proxy-client.key
      server_name: db1.internal        # optional, defaults to the URL host
```

- TLS 1.2 at least. There is no `insecure_skip_verify`: a proxy that
  protects metrics does not read them over an unverified connection.
- The files are read at startup and on every reload: an unreadable file or
  a key that does not match its certificate fails the startup or the
  reload, which then keeps the running configuration. After renewing them,
  reload (`systemctl reload exporter_proxy`); `--check` checks them and
  their dates.
- Handshake and certificate failures count as `unavailable` source errors.

### Cache

For an exporter that is slow or costly to read (a database, a slow SNMP
device), `cache_ttl` keeps a validated result for that long:

```yaml
routes:
  - path: /postgres/metrics
    upstream: http://127.0.0.1:19187/metrics
    cache_ttl: 30s
```

- Off by default. Allowed on `upstream` routes only (files are read
  without cost), at most `1h`, and not with `forward_params` (each target
  would be a cache entry, and probes must be live).
- A cached answer is only served to requests that could have shared the
  read producing it: one obtained with a shorter scrape timeout than a
  request's budget is not handed to it, which reads again (and gets the
  cached answer if no slot is free, rather than `503`). Such an answer
  never replaces a fresh one more requests can use.
- Only valid results are kept: a failure is never cached, the next request
  reads again.
- Answers from such a route carry `Age` (seconds since the read); they
  stay `Cache-Control: no-store` for anything downstream. Requests served
  from the cache are counted in `exporter_proxy_cache_hits_total`.
- One entry per format (text, protobuf). A reload empties the cache.
- Prometheus records samples with the scrape time, not the read time: with
  a `cache_ttl` close to the scrape interval, consecutive scrapes may get
  the same values. Keep it below the scrape interval unless that is
  wanted.

### Formats

The proxy serves the text exposition format, and the delimited protobuf
format that native histograms need:

- When the scraper prefers protobuf in its `Accept` header (Prometheus does
  when native histograms are enabled, `scrape_protocols` starting with
  `PrometheusProto`), an HTTP upstream is asked for protobuf first, then
  text. An upstream answering protobuf (its `Content-Type`) is decoded and
  validated as protobuf, and served with `Content-Type:
  application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;
  encoding=delimited`; anything else is validated and served as text.
- Other scrapers, and `file` routes (always text), get the text format.
- Protobuf validation decodes every metric family and checks metric names,
  label names and values, like the text parser (UTF-8 names allowed). The
  length each message announces is checked against the body before
  anything is decoded, so a malicious upstream cannot make the proxy
  allocate more than `max_body_bytes`. Error messages only give the
  position of the failing family, never content.
- `max_samples` counts a native histogram as one sample, like Prometheus'
  `sample_limit`; classic buckets still count one each, plus `_sum` and
  `_count`.
- Requests asking for different formats do not share reads.

### Metrics filter

`metrics_filter` serves only some metric families of a route, for example
part of node_exporter to a third party (combined with `authorize`):

```yaml
routes:
  - path: /partner/metrics
    upstream: http://127.0.0.1:19100/metrics
    metrics_filter:
      allow: ['node_cpu_.*', 'node_load[0-9]+']   # whole family names, RE2
      deny: ['.*_bytes']                          # wins over allow
    authorize:
      users: [partner]
```

- A family is served when `allow` is empty or one of its patterns matches
  its name, and no `deny` pattern matches. Names are family names: a
  histogram `http_latency_seconds` covers its `_bucket`, `_sum` and
  `_count` series, and is matched as `http_latency_seconds` only: denying
  `http_latency_seconds_bucket` does not hide it.
- Patterns match whole names; each must be a valid regular expression on
  its own.
- The source is validated first, whole (`max_samples` counts what the
  source sent), then filtered. Protobuf messages kept are copied as they
  are; text is re-encoded family by family, sorted by name: the body is no
  longer the source's byte for byte, but the same families, series and
  values.

### Route concurrency limit

`max_concurrent_requests` on a route bounds its source reads within the
listener's limit: a read takes a slot of the listener and one of the
route. Concurrent requests of a route already share one read (below), so
this matters for routes reading several things at once: `forward_params`
routes (each target is a read) and requests in both formats. Without it,
slow probes of many targets can take every slot of the listener and get
its other routes refused with `503`:

```yaml
routes:
  - path: /probe
    upstream: http://127.0.0.1:9115/probe
    max_concurrent_requests: 4     # leaves the other slots to the other routes
    forward_params: { ... }
```

A refused read gives its listener slot back at once; the rejection is
counted in `exporter_proxy_requests_rejected_total{listener}` and logged
with `limit_of=route`.

### Shared reads

Requests for a route that arrive while its source is already being read
(two Prometheus servers in high availability, several scrapers of the same
target) do not read it again: they get the result of the read in progress,
validated once and compressed once.

- Only the first read takes a `max_concurrent_requests` slot: the others
  are neither refused with `503` nor counted in
  `exporter_proxy_requests_in_flight`. They are counted in
  `exporter_proxy_requests_shared_total`.
- Except that a request does not share a read that told the upstream a
  shorter timeout than its own budget (another client's shorter scrape
  timeout): it starts its own read, taking a slot, when one is free, and
  shares the running read otherwise.
- Nothing is cached unless the route sets `cache_ttl` (see "Cache"): a
  request arriving after the read finished reads the source again, so no
  answer is ever older than the scrape that asked.
- The read runs with the route timeout only: the request that started it
  does not cut it short for others with a longer scrape timeout. Every
  request waits at most its own scrape budget; the read goes on while at
  least one request waits for it, and is canceled once none does.
- Every request is counted in `exporter_proxy_requests_total` with its own
  status; source events (`exporter_proxy_samples`,
  `exporter_proxy_source_errors_total`, ...) count reads, once per read,
  except failures, counted for every request that got them.

### Response validation and limits

Content validation is **mandatory and cannot be disabled**: the proxy only
ever serves data that parses as Prometheus metrics. This prevents a
misconfigured or compromised source (wrong file path, local admin page, error
page) from being exposed through the proxy.

- The whole response is read into memory, bounded by `max_body_bytes`, then
  parsed with the official Prometheus text parser
  ([`prometheus/common/expfmt`](https://pkg.go.dev/github.com/prometheus/common/expfmt)),
  not with regular expressions.
- The text exposition format (`version=0.0.4`) and the delimited protobuf
  format are accepted, see "Formats". OpenMetrics is not: it has no parser
  in `prometheus/common`, and content is never served unvalidated.
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
- The scraper's own timeout shortens `timeout` when it is shorter: Prometheus
  and vmagent send it in the `X-Prometheus-Scrape-Timeout-Seconds` header,
  and exporter_proxy gives the source that time minus 500 ms (kept to
  validate and answer; for a scrape timeout of 1 s or less, the whole
  timeout), and never less than 1 s, so that a client announcing a tiny
  timeout cannot make sources answering within a second fail with
  `timeout`. The proxy then
  answers `502` with reason `timeout` before the scraper gives up, instead
  of the scraper reporting a bare timeout. The header can never extend
  `timeout`; an invalid value is ignored. The log
  line of such a failure carries `scrape_budget_ms`.
- The validated body is returned unchanged with
  `Content-Type: text/plain; version=0.0.4; charset=utf-8`.
- Validation guarantees the format, not the harmlessness of the content:
  label values are still free text chosen by the source.
- Each listener serves at most `max_concurrent_requests` requests at the same
  time (default 2, set in `defaults` or per listener). Extra requests are answered immediately with
  `503 Service Unavailable` instead of queuing. A read keeps its slot until
  every request that got its result has written it, so clients reading
  slowly cannot make the proxy hold more answers than that. Once its
  answer is ready, a client has 5 s plus 2 s per MiB of body to read it
  (at most the route timeout plus 10 s): an authenticated client that does
  not read keeps a slot that long, which is the price of the memory bound
  (restrict who may connect with `allowed_networks` and authentication).
- Parsing is linear in the response size, but the parser allocates about
  **10 times the body size** while it runs. Peak memory is therefore bounded
  by roughly `11 × max_body_bytes ×` the sum of `max_concurrent_requests` over
  all listeners: with the defaults (2 MiB, 2 requests) and one listener,
  about 45 MiB in the worst case. Routes with `cache_ttl` add up to two
  kept answers each (text and protobuf, with their gzip copies), and
  answers served from the cache take no slot: an answer replaced in the
  cache stays in memory while slow clients are still reading it (at most
  the write time above). The
  defaults fit common exporters; raise
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

**Prefer mTLS.** A client certificate is checked during the TLS handshake,
before any HTTP processing, at a negligible CPU cost; it cannot be guessed,
and it expires. Basic authentication relies on bcrypt, which is slow on
purpose (about 250 ms of CPU per check at cost 12): every new password tried
by an attacker costs the server that time. exporter_proxy limits this (see
below), but mTLS removes the problem. Use basic authentication when the
scraper cannot present a client certificate, and always with TLS.

Basic authentication without TLS sends the credentials in clear text on the
network. exporter_proxy still starts in that case, but logs a `warn` line for
each such listener at startup (`msg="basic authentication without TLS:
credentials travel in clear text"`), so that it shows up in log alerts.

### Refused authentications

Every refusal is counted in
`exporter_proxy_auth_failures_total{listener,reason}` and logged. Refusals
cost an attacker nothing, so each listener logs at most 10 of them at once,
then 1 per second, at their normal level (`warn`); the others are logged at
`debug` level. The same limit applies to the `warn` lines of rejected
requests (`503`) and rejected sources (`502`), which clients can trigger
too. Its server-side errors (`518`, TLS settings that cannot be
loaded, `error` level; accept errors and handler panics) have the same
limit, counted apart: client noise, including the HTTP/2 and other
net/http errors clients can cause, never hides them.

| `reason` | When | Response | Log |
|----------|------|----------|-----|
| `tls_handshake` | TLS or mTLS handshake failed because of the client: no or invalid client certificate, TLS version or cipher mismatch, client closing during the handshake (port scanners, TCP health checks). Handshakes refused because the server's own TLS settings cannot be loaded (web configuration, certificate, key or client CA, or a server certificate outside its validity dates) are not counted here: they are logged at `error` level and shown by `exporter_proxy_web_config_read_error` | connection closed | `warn` `msg="TLS handshake failed"` with `remote` and `err` |
| `missing_credentials` | Basic auth required, none sent | `401` | `warn` `msg="authentication refused"` with `remote` |
| `invalid_credentials` | Unknown user or wrong password | `401` | `warn`, with `remote` and `user` (truncated to 64 characters; passwords are never logged) |
| `forbidden` | Authenticated, but neither the basic auth user nor a name of the verified client certificate is in the route's `authorize` list | `403` | `warn` `msg="request forbidden: not in the authorize list of the route"` with `route`, `user` and `remote` |
| `certificate_revoked` | Client certificate of an open connection revoked by the `client_crl_file` since (or its revocation no longer checkable: CRL outside its dates) | `403`, connection closed | `warn` `msg="request refused: client certificate revoked or not checkable, closing the connection"` |
| `network_not_allowed` | Client address outside the listener's `allowed_networks` (see below) | connection closed right after it is accepted, before the TLS handshake | `warn` `msg="connection refused: client address not in allowed_networks"` with `remote` |
| `rate_limited` | Too many password checks (see below), or the `rate_limit` of the web configuration reached | `429` with `Retry-After: 1` | `debug` only, to avoid flooding the logs during an attack |

### Route authorization

By default, every client a listener authenticates may read all its routes.
`authorize` restricts a route to some of them, so that teams can share a
listener (one port, one certificate) without reading each other's metrics:

```yaml
routes:
  - path: /app/metrics
    upstream: http://127.0.0.1:9000/metrics
    authorize:
      users: [app-team]                     # basic_auth_users names
      client_sans: [prometheus-app.example.com]  # client certificate names
```

- A request is allowed when its basic authentication user is in `users`,
  or when its client certificate has a subject alternative name (DNS name,
  IP address, email address or URI; DNS names compared without case) in
  `client_sans`. Otherwise it gets `403`.
- Only identities the listener verified count: the user once its password
  is checked, the certificate only when the web configuration verifies it
  against the client CA (`RequireAndVerifyClientCert` or
  `VerifyClientCertIfGiven`). A self-signed certificate accepted by
  `RequireAnyClientCert` matches nothing.
- Authentication comes first: a wrong password still gets `401`.
- `authorize` must list at least one name. A list that cannot match on its
  listener (`users` without `basic_auth_users`, `client_sans` without
  verified client certificates) is reported as a warning at startup, at
  reload and by `--check`; such a route then refuses every request.
- A reload applies changed lists without restarting the listener.

### Client certificate revocation

To cut off one client certificate without replacing the client CA (a
compromised key, a decommissioned scraper), list it in a certificate
revocation list:

```yaml
listeners:
  - name: node
    listen: ":9100"
    web_config_file: /etc/exporter_proxy/web-mtls.yml
    client_crl_file: /etc/exporter_proxy/tls/clients.crl   # PEM or DER, several CRLs allowed
```

- The file is read on every new connection and every request (parsed only
  when it changes): publishing a new CRL applies without reload, and a
  certificate revoked while its connection is open gets `403` at its next
  request, the connection being closed.
- Checked on every handshake, TLS 1.3 session resumption included. A
  revoked certificate fails the handshake (`tls_handshake`); on an open
  connection, the refusal is counted as `certificate_revoked`.
- Fail closed: every certificate of the client's chain except the root
  must be covered by a CRL from its issuer, signed by it. A certificate
  whose issuer has no CRL in the file is refused, and so is every client
  certificate while a CRL is past its `nextUpdate` (or not yet valid):
  republish the CRL in time. `--check` warns 7 days before.
- Every CRL of an issuer in the file counts: a certificate listed by any
  of them is revoked. Only complete CRLs are supported: delta CRLs, CRLs
  with an issuing distribution point (partitioned CRLs, authority
  revocation lists) and CRLs or entries with an unsupported critical
  extension are refused (Go would read them as complete CRLs).
- Requires a web configuration verifying client certificates
  (`RequireAndVerifyClientCert` or `VerifyClientCertIfGiven`). A file that
  does not parse fails the startup or the reload; a CRL outside its dates
  is logged at `error` level and refuses that listener's client
  certificates, the others keep running.
- Like other protections, a reload cannot remove `client_crl_file`:
  restart the service to do so.

### Allowed networks

`allowed_networks` (on a listener or on `metrics`) lists the client
addresses allowed to connect, as single addresses (`192.0.2.10`) or networks
in CIDR notation written with their host bits cleared (`10.0.0.0/8`,
`2001:db8::/32`). A connection from any other address is closed as soon as
it is accepted: before the TLS handshake and before any request, so it
costs no TLS or bcrypt work. Without `allowed_networks`, every address may
connect.

- It adds to the web configuration's authentication, it does not replace
  it: a client in an allowed network still needs its certificate or
  password.
- IPv4 clients of a dual-stack socket (`::ffff:10.1.2.3`) are matched as
  IPv4 addresses.
- A reload applies a new list without restarting the listener. The list
  is also checked on every request: a connection opened before a reload
  that removed its address gets `403` at its next request and is closed
  (counted and logged like a refused connection).
- An empty list is invalid (it would refuse every client), and so is a
  listener on a Unix socket (`systemd:` socket unit with `ListenStream=`
  a path) with `allowed_networks`: its clients have no address. Such a
  listener does not start.
- With systemd, `IPAddressAllow=` and `IPAddressDeny=` filter for the whole
  service; `allowed_networks` filters per listener, also in a container.

### Rate limiting of password checks

Credentials that already passed a bcrypt check are remembered (as a SHA-256
of user, stored hash and password: the password itself is not kept in
memory), so a scraper is checked once and then served without any bcrypt
cost. Only checks of credentials not yet known to be valid are limited, one
at a time, by three limits:

- **per client address: 2 per second, with a burst of 5**, so that a
  brute force from one address cannot use up the checks of other clients;
  an IPv4 address counts alone, an IPv6 address with its whole `/64`
  network (usually one host); clients of a listener on a Unix socket
  (`systemd:` socket unit with `ListenStream=/path`) have no IP address and
  only get the per-listener limit;
- **per listener, all addresses together: 5 per second, with a burst of
  10**, against an attack from many addresses;
- **at most 4 checks running or waiting per listener**, so that requests
  never queue behind slow hashes.

Beyond any of these limits, the request gets `429` without any bcrypt
computation. Requests sent at the same time with the same credentials (an
HA pair of scrapers, several routes scraped together after a restart)
share a single check and its result, so they do not use up the limits.
Verified credentials are kept when a reload restarts the listener.

As a result, a brute force attack costs at most a few bcrypt checks per
second and never slows down a scraper whose credentials are already
verified. A scraper verified for the first time (after a restart or a
password change) while one address attacks still gets its own checks; an
attack from several addresses at once can use up the per-listener budget,
and such a scraper then gets `429` until the attack stops.

These rates assume a check of about 200-250 ms (cost 12 on a current
CPU). With a higher cost, or a slow machine (0.5 s or more per check), a
single address at 2 checks per second keeps the verifications busy all the
time, and a scraper verified for the first time mostly gets `429` during
the attack: keep cost 12, and prefer mTLS, whose refusals cost no bcrypt
check.

Unknown users are checked against a hash with the highest cost of the
configured hashes, so that they take the same time as known ones (no user
enumeration by timing, as long as all hashes have the same cost:
`--check` warns when they do not). bcrypt only uses the first 72 bytes of
a password, so longer passwords are remembered by those 72 bytes. Changing
a password in the web configuration invalidates the remembered credentials
of that user.

The `rate_limit` section of the web configuration (exporter-toolkit format,
`interval` and `burst`) is also supported: it limits **all** requests of the
listener, legitimate ones included, before the web configuration is even
read, and applies when the listener starts (see "Configuration reload").
Prefer the built-in limits above unless all requests must be capped.

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
  `route` is empty for paths that match no route (`404`); `code="499"` for
  clients that disconnected before the answer. Requests refused before
  routing (`401` and `429`, counted in `exporter_proxy_auth_failures_total`,
  and `518`, shown by `exporter_proxy_web_config_read_error`) are not
  included.
- `exporter_proxy_request_duration_seconds{listener,route}` (histogram): total
  time to serve a request (fetch + parse), for matched routes only.
- `exporter_proxy_parse_duration_seconds{listener,route}` (histogram): time
  spent validating the content with the Prometheus parser.
- `exporter_proxy_response_size_bytes{listener,route}` (histogram): size of
  the content read from the source.
- `exporter_proxy_samples{listener,route}` (histogram): number of samples in
  the content read from the source, for valid content only.
- `exporter_proxy_source_errors_total{listener,route,reason}`: rejected
  scrapes, with `reason` in a fixed set: `unavailable` (connection, file or
  HTTP status error), `timeout`, `too_large`, `too_many_samples`, `invalid`
  (parse error), `stale` (file older than `max_age`, or modified more than
  `max_age` in the future).
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
  not included: they are re-read while running (see
  "Configuration reload"), so they are not part of the loaded state.
- `exporter_proxy_config_last_reload_successful` (gauge, 0 or 1): whether
  the last configuration load (startup or `SIGHUP`) succeeded.
- `exporter_proxy_config_last_reload_success_timestamp_seconds` (gauge): time
  of the last successful configuration load.
- `exporter_proxy_auth_failures_total{listener,reason}`: connections and
  requests refused by authentication or access control (see "Refused
  authentications" for the reasons: `tls_handshake`,
  `missing_credentials`, `invalid_credentials`, `rate_limited`,
  `network_not_allowed`, `forbidden`, `certificate_revoked`); the metrics
  endpoint is reported as `listener="metrics"`.
- `exporter_proxy_requests_in_flight{listener}` (gauge): source reads
  holding a concurrency slot, while reading the source or while their
  answer is being written.
- `exporter_proxy_requests_rejected_total{listener}`: requests refused with
  `503` because `max_concurrent_requests` was reached.
- `exporter_proxy_cache_hits_total{listener,route}`: requests answered from
  the cache of a route with `cache_ttl`, without reading the source.
- `exporter_proxy_requests_shared_total{listener,route}`: requests answered
  with the result of a source read started by a concurrent request of the
  same route (shared reads, below).
- `exporter_proxy_web_config_read_error{listener}` (gauge, 0 or 1): 1 while
  the listener's web configuration cannot be applied: the last request
  could not read the file (answered `518`), or the last new TLS connection
  could not load the file, certificate, key or client CA (refused). Both
  are tracked apart, so requests on connections already open do not hide
  a TLS failure. Back to 0 when both succeed again: after a TLS failure,
  requests on connections already open also check (at most once per
  second) whether the TLS settings load again, so the gauge does not wait
  for the next handshake. Requests do not read the client CA, checked on
  every new connection: a CA file briefly missing while being rotated does
  not fail requests on connections already open.
  Reset by a successful reload, except for TLS failures still current
  (server certificate outside its dates, or a handshake failing on the
  server's settings after the reload checked them), shown again right
  after; `listener="metrics"` for the metrics endpoint.

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
# Someone is trying credentials or certificates.
increase(exporter_proxy_auth_failures_total{reason=~"invalid_credentials|rate_limited"}[15m]) > 10
# A web configuration file cannot be read: the listener answers 518.
exporter_proxy_web_config_read_error == 1
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
    allowed_networks:             # optional: only these clients may connect
      - 10.0.0.0/8
      - 192.0.2.10
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
| `service_discovery` | Optional, in `metrics`: `host` required (a name or an address, without scheme, port or brackets); `labels` with classic label names, not starting with `__` nor named `exporter_proxy_listener` or `exporter_proxy_route`. |
| Listeners  | At least one. `name` required, unique, made of letters, digits, `_`, `.`, `-` (it is used as a metric label); `metrics` is reserved for the metrics endpoint. |
| `listen`   | Required, `host:port` with a port from 1 to 65535, or `systemd:<name>` (socket activation, see below); not shared with another listener or with `metrics`. |
| `web_config_file` | Required on every listener and on `metrics`. |
| Routes     | At least one per listener. |
| `path`     | Required, starts with `/`, clean (no `.`, `..`, `//` or trailing `/`), no `?` or `#`, unique within its listener (the same path may exist on another listener). |
| Source     | Exactly one: `upstream` or `file`. `unix_socket` only together with `upstream`. |
| `upstream` | `http://` or `https://`, with a host, without credentials (`user:password@`) or fragment. `unix_socket` requires `http://`. |
| `upstream_tls` | Optional, `https://` upstreams only: `ca_file`, `cert_file` with `key_file`, `server_name`; absolute paths; not empty. No option disables certificate verification. |
| Paths      | `file`, `unix_socket` and `web_config_file` are absolute and clean (`filepath.Clean` leaves them unchanged), so `/var/lib/../../etc/shadow` is rejected. |
| `max_age`  | Required on `file` routes, forbidden on other routes. |
| `metrics_filter` | Optional, on routes: `allow` and/or `deny` patterns (RE2, valid on their own), at least one. |
| route `max_concurrent_requests` | Optional, greater than 0 and at most the listener's resolved `max_concurrent_requests`. |
| `cache_ttl` | Optional, on `upstream` routes without `forward_params`: greater than 0, at most `1h`. |
| `forward_params` | Optional, on `upstream` routes: parameter names made of letters, digits, `_`, `.`, `-`, not set in the `upstream` URL; each with `values` and/or `patterns` (valid RE2), optional `required`. |
| `authorize` | Optional, on routes: `users` and/or `client_sans`, at least one name in all, no empty or duplicate name. |
| `client_crl_file` | Optional, on listeners and `metrics`: absolute path; needs a web configuration verifying client certificates. |
| `allowed_networks` | Optional, on listeners and `metrics`: a non-empty list of addresses or networks in CIDR notation with host bits cleared. Not allowed on a listener whose socket is a Unix socket (refused when it starts). |
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
| `max_body_bytes`          | defaults, route  | `2097152` (2 MiB)   | Larger responses are rejected (`too_large`). At most `1073741824` (1 GiB). |
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

### Health endpoints

The metrics endpoint also serves, like Prometheus:

- `/-/healthy`: `200` while the process serves;
- `/-/ready`: `200` once every listener serves, `503` from the start of the
  shutdown (`SIGTERM`). The ports close right after, during the graceful
  shutdown: to drain a load balancer first, mark the instance out of it
  before stopping the service (a `preStop` hook in Kubernetes, for
  example); `/-/ready` then confirms the state.

They are protected like `/metrics` (web configuration and
`allowed_networks`): a probe needs the same access, so they reveal nothing
to anyone else. For a probe without credentials, give the metrics endpoint
a web configuration without authentication and restrict it with
`allowed_networks`.

### Service discovery

With `metrics.service_discovery`, the metrics endpoint also serves
`/sd`: the routes of the listeners, in the
[Prometheus HTTP service discovery](https://prometheus.io/docs/prometheus/latest/http_sd/)
format, so that Prometheus finds every route without listing them by hand.

```yaml
metrics:
  listen: ":9999"
  web_config_file: /etc/exporter_proxy/web-metrics.yml
  service_discovery:
    host: node1.example.com      # how Prometheus reaches this machine
    labels:                      # optional, added to every target
      dc: par1
```

Each route is one target, `host:port` with the port its listener actually
serves (a `systemd:` TCP socket included), and the labels
`__metrics_path__` (the route path), `__scheme__` (`https` when the
listener serves TLS), `exporter_proxy_listener` and
`exporter_proxy_route`. Listeners on a Unix socket are left out. The list
follows reloads.

The endpoint is protected like `/metrics` (same web configuration and
`allowed_networks`). Credentials are not part of service discovery: set
them in the Prometheus job, and use one job per kind of authentication,
selected with the `exporter_proxy_listener` label:

```yaml
scrape_configs:
  - job_name: exporter_proxy-mtls
    http_sd_configs:
      - url: https://node1.example.com:9999/sd
        tls_config: { ca_file: ca.pem, cert_file: prom.crt, key_file: prom.key }
    tls_config: { ca_file: ca.pem, cert_file: prom.crt, key_file: prom.key }
    relabel_configs:
      - source_labels: [exporter_proxy_listener]
        regex: node
        action: keep
```

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
  `ListenStream=` per socket unit, TCP or Unix). Startup fails if it is
  missing, or if it is a datagram or sequential packet socket
  (`ListenDatagram=`, `ListenSequentialPacket=`).
- Clients of a Unix socket listener all appear as `remote=unix` in logs:
  the path a client binds its socket to is chosen by the client and
  identifies nothing.
- Sockets passed by systemd but not used by any listener are closed, with a
  `warn` log line.
- Listeners using `systemd:` and listeners binding `host:port` can be mixed.
- The service unit must declare the socket units (`Sockets=` or
  `Requires=`/`After=`); `deploy/` does not ship socket units, and its
  service unit binds addresses itself.
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
them owned by `root`, group `exporter_proxy`, with mode `0640`, so that the
service can read but not modify them (like the files in `deploy/config/`).

## Installation

`exporter_proxy` is installed by hand, from a release archive or built
from source. The files of `deploy/` are the ones a package will install.

### Requirements

- Debian 12 or later (systemd 252 or later).
- `procps`, which provides `/bin/kill` for `systemctl reload` (installed by
  default on Debian, missing from minimal container images).

### From a release

Each [release](https://github.com/123-soleil/exporter_proxy/releases)
provides an archive per platform,
`exporter_proxy_<version>_<os>_<arch>.tar.gz` (Linux, FreeBSD, NetBSD,
OpenBSD: `386`, `amd64`, `arm64`, `armv5`, `armv6`, `armv7`; macOS:
`amd64`, `arm64`), and `sha256sums.txt`. An archive holds the static
binary, `README.md`, `CHANGELOG.md`, `LICENSE` and `deploy/`.

```sh
VERSION=0.4.0 ARCH=amd64
BASE=https://github.com/123-soleil/exporter_proxy/releases/download/$VERSION
curl -fsSLO "$BASE/exporter_proxy_${VERSION}_linux_${ARCH}.tar.gz"
curl -fsSLO "$BASE/sha256sums.txt"
sha256sum -c --ignore-missing sha256sums.txt   # must print "OK"
# Proves the archive was built by this repository's CI (from 0.2.0)
gh attestation verify "exporter_proxy_${VERSION}_linux_${ARCH}.tar.gz" --repo 123-soleil/exporter_proxy
mkdir exporter_proxy && tar -xzf "exporter_proxy_${VERSION}_linux_${ARCH}.tar.gz" -C exporter_proxy
cd exporter_proxy && ./exporter_proxy --version
```

Then install the files below from that directory, the binary being
`./exporter_proxy` instead of `bin/exporter_proxy`.

### From source

```sh
make build        # static binary: bin/exporter_proxy
```

### Files

| Source in `deploy/` | Installed as | Notes |
|---------------------|--------------|-------|
| `bin/exporter_proxy` (built), or `exporter_proxy` from an archive | `/usr/sbin/exporter_proxy` | mode `0755` |
| `sysusers/exporter_proxy.conf.exemple` | `/usr/lib/sysusers.d/exporter_proxy.conf` | then `systemd-sysusers` creates the `exporter_proxy` user and group |
| `systemd/exporter_proxy.service.exemple` | `/usr/lib/systemd/system/exporter_proxy.service` | then `systemctl daemon-reload` |
| `default/exporter_proxy.exemple` | `/etc/default/exporter_proxy` | optional `ARGS` (`--log.format=json`, ...) |
| `config/config.yml.exemple` | `/etc/exporter_proxy/config.yml` | contains `CHANGE_ME` |
| `config/web-mtls.yml.exemple`, `config/web-basic.yml.exemple` | `/etc/exporter_proxy/web-*.yml` | contain `CHANGE_ME` |

```sh
sudo install -m 0755 bin/exporter_proxy /usr/sbin/exporter_proxy
sudo install -m 0644 deploy/sysusers/exporter_proxy.conf.exemple /usr/lib/sysusers.d/exporter_proxy.conf
sudo systemd-sysusers
sudo install -m 0644 deploy/systemd/exporter_proxy.service.exemple /usr/lib/systemd/system/exporter_proxy.service
sudo install -m 0644 deploy/default/exporter_proxy.exemple /etc/default/exporter_proxy
sudo install -d -m 0755 /etc/exporter_proxy /etc/exporter_proxy/tls
sudo install -m 0640 -g exporter_proxy deploy/config/config.yml.exemple /etc/exporter_proxy/config.yml
sudo install -m 0640 -g exporter_proxy deploy/config/web-mtls.yml.exemple /etc/exporter_proxy/web-mtls.yml
sudo install -m 0640 -g exporter_proxy deploy/config/web-basic.yml.exemple /etc/exporter_proxy/web-basic.yml
sudo systemctl daemon-reload
```

### What the administrator fills in

1. Replace every `CHANGE_ME` in `/etc/exporter_proxy/config.yml`: listen
   addresses, upstream ports, socket and file paths. Remove the example
   routes that do not apply.
2. Put the server certificate, its key and the client CA in
   `/etc/exporter_proxy/tls/` (owner `root:exporter_proxy`, mode `0640`)
   and set their paths in the web configuration files.
3. For basic authentication, set the bcrypt hash of each user
   (`htpasswd -nBC 12 "" | tr -d ':\n'`).
4. Reconfigure the upstream exporters to listen on `127.0.0.1` only;
   otherwise their port remains reachable without authentication and the
   proxy can be bypassed.
5. Give the `exporter_proxy` user access to the sources it reads: read
   permission on metric files, write permission on Unix sockets (usually by
   adding it to the group owning them).
6. Check, then start:

```sh
sudo -u exporter_proxy exporter_proxy --check --config /etc/exporter_proxy/config.yml
sudo systemctl enable --now exporter_proxy
```

### systemd hardening

The unit is `Type=notify`: exporter_proxy tells systemd it is ready once
every listener serves, so `systemctl start` waits for it (and fails if a
listener cannot start), and a `systemctl reload` sent right after a start
waits too, instead of killing a process that has not set up its `SIGHUP`
handling yet.

The unit follows a least-privilege profile: dedicated user, no capability
(`CapabilityBoundingSet=` empty), read-only file system
(`ProtectSystem=strict`, `ProtectHome=yes`), private `/tmp` and devices,
kernel protections, `ProtectProc=invisible` and `ProcSubset=pid`,
`MemoryDenyWriteExecute=yes`, address families limited to `AF_UNIX`,
`AF_INET` and `AF_INET6`, system calls limited to `@system-service` without
`@privileged`. All directives exist in systemd 252 (Debian 12).

The unit was tested as installed by the commands above on Debian 12
(systemd 252, in a container with systemd as PID 1): `--check` as the service
user, start, scrapes through an mTLS listener (TCP exporter) and a basic
authentication listener (exporter on a Unix socket under `/run`, metrics file
under `/var/lib`), refused TLS handshake and wrong password counted,
`systemctl reload` (valid then invalid configuration, same PID) and
`systemctl stop` (clean exit). No system call was denied by the filter.

`systemd-analyze security` rates it **1.4 (OK)**. The remaining items are
needed by the service or depend on the site:

| Item | Reason |
|------|--------|
| `RestrictAddressFamilies` allows `AF_INET`/`AF_INET6`, no `PrivateNetwork=` | The proxy listens and connects to exporters. |
| `RestrictAddressFamilies` allows `AF_UNIX` | Exporters on Unix sockets. |
| No `PrivateUsers=` | It would hide supplementary groups, which grant access to sockets and metric files. |
| No `IPAddressAllow=`/`IPAddressDeny=` | Scraper addresses are site specific; add them in a local drop-in if wanted. |
| `@resources` system calls allowed | The Go runtime raises `RLIMIT_NOFILE` at startup. |

Connecting to a Unix socket works under `ProtectSystem=strict`: only the
permission of the socket file matters, not the read-only mount.

### Docker

The `Dockerfile` builds a minimal image: a static binary on
[distroless](https://github.com/GoogleContainerTools/distroless)
`static-debian13:nonroot`, with no shell or package manager, running as
uid/gid `65532`. The entrypoint is `exporter_proxy`, and the configuration
is read from `/etc/exporter_proxy/config.yml` by default. Base images are
pinned by digest and kept up to date by Dependabot.

Build the image (no registry image is published yet):

```sh
docker build -t exporter_proxy:0.4.0 \
  --build-arg VERSION=0.4.0 --build-arg REVISION="$(git rev-parse HEAD)" .
# Other platforms, cross-compiled without emulation:
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t exporter_proxy:0.4.0 .
```

Run it:

```sh
docker run -d --name exporter_proxy --restart unless-stopped \
  --network host \
  --user 65532:"$(getent group exporter_proxy | cut -d: -f3)" \
  -v /etc/exporter_proxy:/etc/exporter_proxy:ro \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --stop-timeout 30 \
  exporter_proxy:0.4.0
```

`deploy/docker/compose.yml.exemple` is the same with Docker Compose.

| Topic | In a container |
|-------|----------------|
| Configuration | Mount the **directory** (`/etc/exporter_proxy`), read-only, not single files: a file replaced atomically (editors, configuration management) would stay the old one in the container, and a reload would not see the change. Paths in `config.yml` and in the web configurations (certificates, keys, metric files) are paths inside the container. |
| File permissions | The process runs as uid `65532`. Give it read access through its group: files `root:<gid>` mode `0640`, and `--user 65532:<gid>` (the `exporter_proxy` group of the host, for example). |
| Network: exporters on the host | `--network host`: the proxy reaches exporters listening on `127.0.0.1` of the host, as with the systemd unit, and binds the `listen` addresses of `config.yml` on the host. Without capabilities, listen ports must be 1024 or above. |
| Network: exporters in containers | A bridge network shared with the exporters, upstreams by service name (`http://node-exporter:9100/metrics`), and only the proxy's ports published (`-p 443:9443`). The exporters' ports stay unpublished. |
| File routes, Unix socket upstreams | Mount their directories (read-only for files; the socket's directory for Unix sockets, with the socket file writable by the container's uid or gid). |
| Reload | `docker kill --signal HUP exporter_proxy` (`systemctl reload` equivalent): same all-or-nothing rules, see "Configuration reload". |
| Stop | `docker stop` sends `SIGTERM`; `--stop-timeout 30` (`stop_grace_period: 30s`) leaves the 15 s graceful shutdown time to finish (Docker's default is 10 s). |
| Logs | On stderr: `docker logs exporter_proxy`. Options as arguments after the image name: `exporter_proxy:0.4.0 --log.format=json`. |
| Check | `docker run --rm --user 65532:<gid> -v /etc/exporter_proxy:/etc/exporter_proxy:ro exporter_proxy:0.4.0 --check` |
| Health | No shell in the image, so no `HEALTHCHECK`. Orchestrators probe `/-/healthy` and `/-/ready` on the metrics endpoint (see "Health endpoints"); Prometheus scraping the metrics endpoint (`up`) remains the main health check. |
| Not available | systemd socket activation (`listen: "systemd:<name>"`). |

## Usage

Command line:

```sh
exporter_proxy --config /etc/exporter_proxy/config.yml
exporter_proxy --version
```

| Flag        | Description                                                        |
|-------------|--------------------------------------------------------------------|
| `--config`  | Path to the configuration file (default `/etc/exporter_proxy/config.yml`). |
| `--check`   | Check the whole setup without starting anything, then exit `0` (no problem) or `1` (see below). |
| `--log.level` | Minimum log level: `debug`, `info`, `warn`, `error` (default `info`). |
| `--log.format` | Log format: `logfmt` or `json` (default `logfmt`).              |
| `--log.access` | Log one line per served request (default off).                  |
| `--probe`      | With `--check`: also read every source once (see below).        |
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
closed or if a listener failed while running; `2` for a command-line usage
error).

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
  code, duration, size, client address), useful for debugging and as an
  audit of who read what, but noisy at normal scrape rates. Verified
  identities are added: `user` (basic authentication, once its password is
  checked) and `client_cert` (common name, else first subject alternative
  name, of a client certificate verified against the client CA), each
  truncated to 64 characters; an unverified header or certificate never
  appears.
- Context is always in separate fields, never concatenated into `msg`. No
  colors are used.

### Checking a setup (`--check`)

`--check` goes further than validating the configuration syntax. It starts
nothing and binds no port. It reports every finding (one log line each, not
only the first one) and exits with `0` if there is no problem, `1`
otherwise; warnings do not fail the check:

- the main configuration is parsed and validated (same rules as at startup,
  each validation problem on its own line);
- each web configuration file (listeners and `metrics`, checked once when
  shared) is valid for exporter-toolkit: strict YAML, valid bcrypt hashes,
  certificate and key readable and matching, client CA readable;
- the certificates (files or inline) are within their validity dates: an
  expired or not-yet-valid server certificate is a problem, one expiring
  within 30 days is a warning; an intermediate outside its dates is a
  warning (clients usually skip an expired cross-signature). A client CA bundle is judged as TLS uses it:
  expired, not-yet-valid or unparseable certificates in it are warnings
  (normal while rotating CAs), and it is a problem only if none is
  currently valid. This date check is stricter than startup, reload and
  runtime, which accept a bundle of only expired CAs (every client would
  then be refused): run `--check` after changing certificates;
- the rules exporter_proxy adds to exporter-toolkit's (see "Configuration
  reload" and "Refused authentications") are checked too, like at startup;
- an `authorize` list that cannot match on its listener is a warning;
- each `client_crl_file` parses and is within its dates (a warning 7 days
  before its next update);
- basic authentication without TLS is a warning, and so are
  `basic_auth_users` hashes with different bcrypt costs (response times
  would tell users apart);
- each `file` route: the file exists, is a regular file, is readable and is
  not older than `max_age` nor more than `max_age` in the future;
- each `unix_socket` route: the path exists, is a socket and is writable by
  the current user (required by `connect()`).

With `--probe`, `--check` also reads every route's source once, with the
same code, timeout and limits as the proxy, and validates its content: an
unreachable exporter, a TLS failure, a page that is not metrics or too many
samples is a problem, more than 80% of `max_samples` a warning. Run it as
the service user, before a reload or in a deployment pipeline. Routes that
need a query parameter (`required` in `forward_params`) are not read, with
a warning.

Example output:

```
level=ERROR msg="check: problem" where="listener \"files\" route \"/batch/metrics\"" problem="file: open /var/lib/batch/metrics.prom: no such file or directory"
level=WARN msg="check: warning" where="listener \"node\" web_config_file /etc/exporter_proxy/web-mtls.yml" warning="cert_file /etc/exporter_proxy/tls/node.crt: certificate \"CN=node\" expires on 2026-11-30T00:00:00Z"
level=ERROR msg="check failed" path=/etc/exporter_proxy/config.yml problems=1 warnings=1
```

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

On `SIGHUP` (`systemctl reload exporter_proxy`), the configuration file is
read (a `SIGHUP` received while starting is applied once serving, it never
stops the process), validated, its web configuration files are validated and every new
address is bound **before** anything changes. A reload is all or nothing:

- if any step fails (invalid configuration, invalid web configuration, port
  in use, new `systemd:` socket), the error is logged, the running
  configuration is kept unchanged and
  `exporter_proxy_config_last_reload_successful` is set to `0`;
- otherwise the new configuration is applied, `exporter_proxy_config_hash`
  and the reload metrics are updated and the log line
  `msg="configuration reloaded" ... changed=true|false` tells whether the
  file content changed.

How each listener is applied (listeners are matched by `name`, addresses by
the `listen` value as written):

| Change | Effect |
|--------|--------|
| Same `name`, `listen` and `web_config_file`, and the same TLS, HTTP/2, `rate_limit` and client certificate settings (`client_auth_type`, client CA content, `client_allowed_sans`) in that file | Routes and limits are swapped atomically; the socket and open connections are kept. |
| Same `listen`, other `web_config_file` or one of these settings changed in it, or listener renamed | The socket is duplicated: the port is never closed. A new server starts on it and the previous one stops gracefully: its open connections, including idle keep-alive ones accepted under the previous client certificate settings, are closed, and clients reconnect under the new ones. Until then, requests on those connections get the new routes and `allowed_networks` if the new listener has the same web configuration file, TLS and client certificate settings (the previous server's authentication then enforces the same), `503` otherwise. |
| New `listen` address | Bound at reload. |
| New `systemd:<name>` | Refused: systemd passes its sockets at startup only; restart the service. |
| Listener removed | Stopped gracefully: in-flight requests complete (up to 15 s), then the port is closed. New requests on connections still open get `503`. |

During a reload, requests already running on the previous handler still
count against its `max_concurrent_requests`, while new requests use the new
one: for a few seconds, a listener may serve up to twice its limit. Metric
series of removed listeners and routes are deleted, and requests of these
still draining do not create them again. Idle upstream connections of a
replaced or stopped handler are closed.

Since the address is compared as written, changing `":9100"` into
`"0.0.0.0:9100"` is seen as a new address and fails with "address already in
use": restart the service for such a change.

Web configuration files themselves do not need a reload, they are re-read
while running, like exporter-toolkit does:

- `basic_auth_users` and `http_server_config.headers` on every request: a
  user added, removed or with a new password takes effect immediately;
  hashes and headers are checked like at startup (a malformed hash, or a
  header or value outside exporter-toolkit's list, makes the file invalid,
  so requests get `518`);
- TLS settings (certificate, key, client CA content) on every new
  connection, so a renewed certificate or CA is picked up without restart.
  Connections already open are not checked again: to cut off clients after
  replacing a client CA, reload (the listener restarts and closes them).

Whether a listener uses TLS at all, HTTP/2 (`http_server_config.http2`),
`rate_limit`, whether it requires basic authentication and its client
certificate settings are read when the listener starts. Users added to
`basic_auth_users` apply at once, without restarting the listener;
removing them all makes a reload fail (see below). Authentication
fails closed, never open:

- a listener started with `basic_auth_users`, or whose file gained users
  while running, answers `518` if the file loses all its users (emptied or
  truncated while being rewritten), until the file is fixed or a restart
  removes authentication;
- the client certificate settings of a TLS listener (`client_auth_type`,
  whether a client CA is configured, `client_allowed_sans`) are fixed while
  it runs: if its file differs, tighter or looser (for example a file cut
  before `client_auth_type`), new connections are refused until the file
  is fixed, or until a reload applies tighter settings or a restart looser
  ones (counted in `exporter_proxy_web_config_read_error`, not as client
  failures). Only the content of the client CA, like the server
  certificate and key, can change without reload, for rotation.

A `client_auth_type` that verifies client certificates
(`RequireAndVerifyClientCert`, `VerifyClientCertIfGiven`) requires a client
CA (`client_ca_file` or `client_ca`): without one, crypto/tls would verify
them against the system roots and accept any client certificate from a CA
the machine trusts, so the file is invalid (exporter-toolkit accepts it).
Conversely, a client CA with a `client_auth_type` that does not verify
certificates (`RequestClientCert`, `RequireAnyClientCert` or its old name
`RequireClientCert`) would be ignored, any self-signed certificate being
accepted: the file is invalid too, as is a client CA containing no
certificate. With HTTP/2 enabled (the default) and `min_version` below
`TLS13`, a `cipher_suites` list must include
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` or
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, which net/http requires for
HTTP/2: otherwise the listener would stop right after starting. A server
certificate (the leaf) outside its validity dates makes that listener's
new TLS connections fail as a server-side error
(`web_config_read_error`), whether it is found at startup or reload (also
logged at `error` level; the other listeners keep running) or expires
while running.
`client_allowed_sans` requires a `client_auth_type` that verifies client
certificates (`RequireAndVerifyClientCert` or `VerifyClientCertIfGiven`):
otherwise any client could present a self-signed certificate carrying an
allowed name, so the file is invalid; an empty list is invalid too. The
names are also checked when a client resumes a TLS session, and a client
without a certificate is refused.

A reload applies changed client certificate settings or client CA content
by restarting the listener on its socket, which closes the connections
accepted under the previous ones.

**A reload never weakens authentication.** A reload that would remove or
lower a protection (basic authentication removed, a client certificate no
longer required or no longer verified, client CA or `client_allowed_sans`
removed, TLS lost), including for the previous listener of a port when
listeners are renamed or swap addresses, is refused as a whole: the error
names the listeners, the running configuration is kept and
`exporter_proxy_config_last_reload_successful` is set to 0. A web
configuration caught empty or half-written therefore never lowers
authentication. To lower it on purpose, restart the service (`systemctl
restart exporter_proxy`); with systemd socket activation, the sockets stay
open during the restart.

After changing these settings to strengthen them, reload (the listener is
then restarted on its socket, even if its `web_config_file` path is the
same) or restart. Until then, the listener keeps its previous settings;
adding `tls_server_config` to the file of a plain HTTP listener makes its
requests get `518` until the reload, instead of serving in clear text. Replace these files atomically
(write a temporary file, then rename it) so that a half-written file is
never read.

### Scraping from Prometheus or VictoriaMetrics

Prometheus (`prometheus.yml`), vmagent and single-node VictoriaMetrics
(`-promscrape.config`) use the same `scrape_configs` format. Example for the
configuration of `deploy/config/config.yml.exemple`: an mTLS listener on
port 9100, a basic auth listener with two routes on port 9443, and the proxy
metrics on port 9999.

```yaml
scrape_configs:
  # mTLS listener "node": node_exporter behind /metrics.
  - job_name: node
    scheme: https
    metrics_path: /metrics
    # Optional. exporter_proxy reads this timeout from the request header
    # and answers before it expires; keep the route timeout (default 10s)
    # at or above it so that the scraper's timeout is the one that applies.
    scrape_timeout: 10s
    tls_config:
      ca_file: /etc/prometheus/tls/exporter_proxy-ca.crt
      cert_file: /etc/prometheus/tls/scraper.crt
      key_file: /etc/prometheus/tls/scraper.key
    static_configs:
      - targets: ["server1.example.org:9100", "server2.example.org:9100"]

  # Basic auth listener "apps": one job per route (metrics_path).
  - job_name: app
    scheme: https
    metrics_path: /app/metrics
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/exporter_proxy.password
    tls_config:
      ca_file: /etc/prometheus/tls/exporter_proxy-ca.crt
    static_configs:
      - targets: ["server1.example.org:9443"]

  - job_name: batch
    scheme: https
    metrics_path: /batch/metrics
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/exporter_proxy.password
    tls_config:
      ca_file: /etc/prometheus/tls/exporter_proxy-ca.crt
    static_configs:
      - targets: ["server1.example.org:9443"]

  # exporter_proxy's own metrics (metrics listener, mTLS).
  - job_name: exporter_proxy
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/tls/exporter_proxy-ca.crt
      cert_file: /etc/prometheus/tls/scraper.crt
      key_file: /etc/prometheus/tls/scraper.key
    static_configs:
      - targets: ["server1.example.org:9999", "server2.example.org:9999"]
```

- The scraper trusts the CA that signed exporter_proxy's server certificate
  (`ca_file`). If the certificate names the host by DNS name and the target
  uses another name or an IP address, set `tls_config.server_name`.
- Each route of a listener is a job with its own `metrics_path`; all of them
  share the listener's authentication.
- `password_file` keeps the password out of the scrape configuration; the
  file must be readable by Prometheus or vmagent only.
- The scraper's `scrape_timeout` (sent in the
  `X-Prometheus-Scrape-Timeout-Seconds` header) caps the time given to the
  source, so a slow source gives a `502` with reason `timeout`
  (`exporter_proxy_source_errors_total`) before the scraper gives up. The
  route `timeout` remains the upper bound: if it is shorter than
  `scrape_timeout`, it is the one that applies.
- Each route counts against `max_concurrent_requests` of the listener
  (default 2) when their scrapes overlap; several scrapers of the same
  route (high availability pairs) share one read and take one slot. With
  many routes on one listener, raise it.

These files were validated with `promtool check config` (Prometheus 3.7)
and `vmagent -dryRun` (vmagent 1.128), then used to scrape a running
exporter_proxy: all targets were up in both.

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

### Continuous integration

GitHub Actions (`.github/workflows/`):

| Workflow | When | What |
|----------|------|------|
| `ci.yml` | Pull requests to `main`, pushes to `main` | Code checks (`gofmt`, `go mod tidy`, `go vet`, golangci-lint); dependency checks (`go mod verify`, `govulncheck`, and on pull requests GitHub's dependency review, which refuses a new dependency with a known vulnerability); tests with the race detector on Linux, Go 1.26 and the latest Go, and `make build`; the Docker image built for `linux/amd64`, `linux/arm64` and `linux/arm/v7`, then run as documented in "Docker" (`test/docker/run.sh`: hardened, uid 65532, serving, reload with `SIGHUP` after an atomic file replacement, clean stop). |
| `integration.yml` | Pull requests to `main`, pushes to `main` | `test/systemd/run.sh` under the runner's real systemd: installation from `deploy/` as described above, the hardened unit, socket activation on port 443 (no capability), TLS and basic auth, `--check`, reload (successful and failed) without restarting the process, clean stop. |
| `codeql.yml` | Pull requests to `main`, pushes to `main`, every Monday | CodeQL static analysis of the code (`security-and-quality` queries), results in the Security tab. |
| `security.yml` | Every Monday, or by hand | `go mod verify` and `govulncheck` on `main`, for vulnerabilities published after a merge. |
| `release.yml` | A GitHub release is published | Tests and `govulncheck`, then `make build` for Linux, macOS, FreeBSD, NetBSD and OpenBSD (386, amd64, arm64, armv5/6/7 where supported), each packaged as `exporter_proxy_<tag>_<os>_<arch>.tar.gz` (binary, README, CHANGELOG, LICENSE, `deploy/`) and uploaded to the release with `sha256sums.txt` and a build provenance attestation. |

Dependabot proposes Go module, GitHub Actions and Docker base image updates every week, a
week after their release. Actions are pinned by commit SHA.

`make test` includes end-to-end tests (`cmd/exporter_proxy/e2e_test.go`)
that run the whole program with a certificate authority, server and client
certificates generated at test time. They check that the mTLS listener
accepts a valid client certificate and refuses a missing one, one from
another CA, an expired one, one without client usage and TLS 1.1; that
basic authentication over TLS works and that neither credentials nor other
client headers nor the client query string reach the upstream exporter; that
plain HTTP on a TLS port is refused; that the metrics endpoint enforces its
own web configuration; and that a renewed server certificate is used for new
connections without restart.

Tests must not be run from a `noexec` mount: `go test` executes the test
binaries it builds in `$TMPDIR`. On a server where `/tmp` is `noexec`, point
`GOTMPDIR` to an executable directory.

## License

[Apache License 2.0](LICENSE).

## References

- [Prometheus exporter-toolkit web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
