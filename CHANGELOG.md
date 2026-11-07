# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project README describing goals, design and configuration format.
- Design: route sources may be an HTTP exporter over TCP, an HTTP exporter
  over a Unix domain socket, or a static Prometheus text file.
- Design: mandatory validation of every response with the Prometheus text
  parser, bounded by `max_body_bytes` and `timeout`, with parse duration,
  response size and per-reason error metrics.
- Design: `max_samples` limit per response (default 24000) and
  `max_concurrent_requests` limit per listener (default 2, extra requests
  get `503`), with sample count, in-flight and rejection metrics.
- Design: absolute, clean paths enforced for `file` and `unix_socket`;
  mandatory `max_age` for file routes with `stale` rejection and a file
  modification time metric.
- Design: `--version` flag and `exporter_proxy_build_info` metric.
- Design: `exporter_proxy_config_hash` metric (SHA-256 of the loaded
  configuration file, first 48 bits).
- Design: `--check` flag validating the configuration and the files it
  references (web configurations, TLS material, metric files, sockets).
- Design: configuration reload on `SIGHUP` with reload status metrics.
- Design: exporter-style logs via `promslog` (`logfmt` by default, `json`
  optional, `--log.level`), access log disabled by default (`--log.access`).
- Command skeleton: `--version` (one line), `--log.level`, `--log.format`,
  `--config`, UTC log timestamps, reliable exit codes (0, 1, 2).
- `Makefile` with `help`, `build` (static binary, version injected with
  `-ldflags -X`), `test`, `lint` and `clean` targets.
- Strict configuration loading: unknown keys, empty files and multiple YAML
  documents are errors; limits resolve from route or listener, then the
  `defaults` section, then built-in defaults (documented in the README).
- Configuration validation reporting all problems at once: unique listener
  names and addresses, clean unique route paths, exactly one source per
  route, `http://` upstreams without credentials, absolute clean paths,
  required `web_config_file`, `metrics` section and `max_age` on file routes,
  strictly positive limits.
- Configuration hash (first 48 bits of SHA-256), logged at startup.
- Metric sources: HTTP over TCP, HTTP over a Unix socket and static files,
  bounded by `timeout` and `max_body_bytes` (decompressed size), with typed
  failure reasons (`unavailable`, `timeout`, `too_large`, `stale`); no proxy
  from the environment, no redirects, no client header forwarded, FIFOs and
  non-regular files rejected without blocking.
- Mandatory content validation with the Prometheus text parser (UTF-8
  names), `max_samples` limit counted like Prometheus' `sample_limit`, parse
  duration measured; parse errors never include the offending content.
  Benchmark on synthetic data in `internal/content`.
- Built-in defaults sized for common exporters, with exceptions set per
  route or listener: `max_body_bytes` 2 MiB, `max_samples` 24000 and
  `max_concurrent_requests` 2, bounding the worst-case parsing memory to
  about 45 MiB per listener.
- HTTP handler per listener: exact path routing, `GET`/`HEAD` only (`405`
  otherwise, `404` for unknown paths), `max_concurrent_requests` slots with
  immediate `503`, `502` with the failure reason only, failures logged at
  `warn`, optional access log, hooks for the proxy metrics.
- Listeners configured with exporter-toolkit web configuration files (TLS,
  mTLS, basic auth, re-read while running): web configurations validated
  and every address bound before serving, graceful shutdown on `SIGTERM` and
  `SIGINT` (15 s), HTTP server timeouts, `--log.access` flag.
- Startup warning for listeners using basic authentication without TLS.
- systemd socket activation: `listen: "systemd:<name>"` takes the socket named
  by `FileDescriptorName=`, so ports below 1024 need no capability; unused
  passed sockets are closed.
- Proxy metrics on the `metrics` listener (own web configuration, `systemd:`
  supported): requests, durations, parse time, response size, samples,
  source errors by reason, in-flight and rejected requests, file
  modification time, `build_info`, configuration hash and load status, plus
  Go and process metrics; series pre-initialized at 0.
- `--check`: validates the configuration, the web configuration files
  (exporter-toolkit validation, certificate validity dates with a 30-day
  expiry warning, non-empty client CA), metrics files (present, regular,
  readable, fresh) and Unix sockets (present, writable), reporting every
  finding on its own line; exit code 0 or 1.
- Configuration reload on `SIGHUP`, all or nothing: unchanged listeners keep
  their socket and connections, a listener on the same address with a new
  web configuration or name gets a duplicate of the socket (the port is
  never closed), removed listeners stop gracefully; metrics of removed routes
  are deleted; `config_last_reload_successful` set to 0 on failure.
- Reload restarts a listener on its socket when TLS, HTTP/2 or `rate_limit`
  change in the same web configuration file, instead of keeping the old
  settings (TLS enabled in the file was ignored until restart).
- Requests of removed listeners still draining no longer recreate their
  metric series; `requests_in_flight` stays exact when a listener is
  removed and added back.
- Requests whose client disconnected are recorded with code `499` instead
  of `502` (a `502` is still written, never an empty `200`).
- An unreadable or invalid web configuration file answers `518` with the
  body `web configuration unreadable` (was a bare `500`), and sets the new
  gauge `exporter_proxy_web_config_read_error{listener}` to 1 until the file
  is read successfully again; TLS connections refused for the same reason
  set it too.
- Client certificate settings fail closed too: `client_auth_type`, the
  presence of a client CA and `client_allowed_sans` are fixed while a TLS
  listener runs; a web configuration that differs (a file cut before
  `client_auth_type` let clients in without a certificate) refuses new
  connections until a reload (tighter settings) or a restart (looser). The client CA content can still be rotated
  without reload. A reload that changes these settings or the client CA
  content restarts the listener, closing connections opened under the
  previous settings.
- A verifying `client_auth_type` without a client CA is invalid: client
  certificates would be verified against the system roots. A client CA
  with a non-verifying `client_auth_type` (ignored CA) or without any
  certificate is invalid too, at startup, reload, `--check` and while
  running.
- A `cipher_suites` list without the cipher HTTP/2 requires (with HTTP/2
  on and `min_version` below TLS 1.3) is invalid: the listener stopped
  right after starting or after a reload, stopping the process; a listener
  failing that way also releases its socket.
- A plain HTTP listener whose web configuration enables TLS answers `518`
  until a reload, instead of serving in clear text.
- `OPTIONS *` goes through authentication instead of net/http's automatic
  empty `200`; HTTP/2 handler panics use the server log budget; Unix
  socket clients all show as remote address `unix`, so a client cannot
  shape it (with the path it binds to) to hide its handshake failures
  behind the server-side marker.
- A reload never weakens authentication: one that would remove basic
  authentication, lower client certificate requirements or lose TLS (also
  through renamed or swapped listeners) is refused, keeping the running
  configuration; lowering authentication on purpose takes a restart. A web
  configuration caught half-written by a reload can no longer open a
  listener.
- A server certificate (the leaf; an expired cross-signed intermediate is
  left to clients, `--check` warns about it) outside its validity dates is
  refused on every new TLS connection (TLS 1.3 session resumption
  included, the certificate being checked and pinned per connection) as a
  server-side failure (`web_config_read_error`), instead of being sent and
  counted as client `tls_handshake` failures; found at startup or reload,
  it is logged, reported in `web_config_read_error` from the start and
  again after a reload resetting the metrics, and only stops that
  listener's TLS connections. `min_version` above `max_version` is
  invalid. A file whose ciphers cannot carry the HTTP/2
  the listener offers is refused at runtime too. Users found by a reload that
  keeps a listener are required from then on (fail closed). The client CA
  pool is checked as read once per connection (no second read a rewrite
  could slip between). A reload that only finds new users in a web
  configuration keeps the listener instead of restarting it.
- Sockets passed by systemd are closed and reported even when no listener
  uses `systemd:`; Unix socket connections keep net/http's graceful
  half-close.
- systemd datagram and sequential packet sockets are refused at startup
  (they failed on Accept, or bypassed the Unix client address masking).
- `web_config_read_error` returns to 0 when TLS settings load again, also
  through requests on connections already open (at most one recheck per
  second, never clearing a failure recorded meanwhile), without waiting for
  a new handshake. Requests no longer read the client CA, so one briefly
  missing during a rotation does not answer `518` on open connections.
- `--check` judges client CA bundles like TLS does (expired or unparseable
  certificates are warnings while one is valid, normal while rotating CAs)
  and checks the dates of inline certificates; startup and reload report
  every web configuration breaking exporter_proxy's rules at once.
- The client CA check is cached by content hash (a rewrite keeping size
  and modification time is checked again), instead of parsing the bundle
  every time.
- A `rate_limit` with an `interval` but no `burst` is invalid: it refused
  every request.
- `client_allowed_sans` requires a verifying `client_auth_type` (with an
  unverified certificate, names could be forged) and cannot be empty; it is
  also checked on TLS session resumption, and a client without a
  certificate is refused (exporter-toolkit panicked).
- Basic authentication fails closed: a listener started with
  `basic_auth_users`, or whose file gained users while running, answers
  `518` if its web configuration loses its users
  (emptied or truncated file) instead of serving without authentication;
  removing authentication takes a restart (a reload that would remove it
  is refused).
- Malformed bcrypt hashes in a web configuration changed while running make
  it invalid (`518`), like at startup.
- Handshakes refused because of the server's own TLS settings are no longer
  counted as client `tls_handshake` failures; `web_config_read_error`
  tracks request and TLS reads apart, so open connections do not hide a TLS
  failure, and is reset by a successful reload.
- A `SIGHUP` received while starting no longer stops the process.
- File routes and `--check` reject a modification time more than
  `max_age` in the future.
- Refusal and server-side error logs are rate limited per listener, with
  separate budgets so client noise (including HTTP/2 and other net/http
  errors clients can cause) never hides server errors (burst 10,
  then 1 per second; the rest at debug level).
- The time a scraper's timeout header leaves to the source is at least
  1 s, so that a client announcing a tiny timeout cannot make sources
  answering within a second fail with `timeout`; the `warn` lines of
  rejected requests and sources are rate limited like refusals.
- Identical credentials sent at the same time share one bcrypt check, and
  verified credentials survive a listener restart on reload, so that
  scrapers starting together no longer get `429`.
- Invalid content is no longer counted in `exporter_proxy_samples`; events
  of listeners added by a reload are recorded as soon as they serve; timeout
  messages name the limit that fired (route or scraper's timeout).
- Headers of a web configuration file changed while running are checked
  against exporter-toolkit's allowed list, like at startup (a forbidden
  header was sent on every response); such a file answers `518`.
- A client that leaves while its password check waits gets `429` and is
  counted, never an empty `200`.
- Clients of a listener on a Unix socket only get the per-listener password
  check limit, instead of sharing one per-client bucket.
- A file read still running during a reload no longer recreates the
  `file_modified_timestamp_seconds` series of a route that stopped being a
  file route.
- `max_body_bytes` is limited to 1 GiB: a value near the int64 maximum
  overflowed and made every route answer an empty `200`.
- Unknown users are checked against a hash with the cost of the configured
  hashes (was always cost 10), so that user names cannot be told apart by
  timing; per-client limits group IPv6 addresses by `/64`.
- `file_modified_timestamp_seconds` is deleted when a route stops being a
  file route.
- `golang.org/x/net` upgraded to v0.62.0 (GO-2026-6866, GO-2026-6860, not
  reachable from the code).
- `--check` stops at the first certificate of `cert_file` even when it
  cannot be parsed, instead of checking the next one as the leaf.
- Idle upstream connections are closed when a handler is replaced or
  stopped; a second `SIGTERM` or `SIGINT` stops the process without waiting
  for the graceful shutdown.
- End-to-end tests with a test PKI: mTLS (valid, missing, foreign CA,
  expired, wrong usage, TLS 1.1), basic auth over TLS, nothing from the
  client forwarded upstream, plain HTTP on a TLS port, metrics endpoint
  protection, server certificate rotation without restart.
- Deployment files: commented configuration and web configuration examples,
  `/etc/default` file for extra options, sysusers declaration and hardened
  systemd unit with reload (`systemd-analyze security`: 1.4).
- TLS and basic authentication enforced in-process (web configuration still
  validated and TLS settings built with exporter-toolkit): every refusal is
  logged and counted in `exporter_proxy_auth_failures_total{reason}`
  (`tls_handshake`, `missing_credentials`, `invalid_credentials`,
  `rate_limited`).
- Rate limiting of uncached bcrypt password checks (2/s, burst 5 per
  client IP address, 5/s, burst 10 and at most 4 pending per listener,
  answered `429`), so that a brute force from one address does not lock
  out other scrapers and no queue builds up;
  verified credentials are cached as a SHA-256 and never limited. The web
  configuration `rate_limit` is supported and applied before the web
  configuration is read.
- Documentation: mTLS preferred over basic authentication.
- Documentation: Prometheus and VictoriaMetrics (vmagent) scrape examples for
  mTLS and basic auth listeners, validated with promtool and vmagent.
- Documentation: `procps` requirement for `systemctl reload`; the unit was
  tested on Debian 12 (systemd 252) as installed by the README.
- The scraper's timeout (`X-Prometheus-Scrape-Timeout-Seconds`, sent by
  Prometheus and vmagent) shortens the source read, minus 500 ms to answer:
  a slow source gives a `502 timeout` before the scraper gives up. It never
  extends the route `timeout`.
- `.gitignore` for Go builds, local configuration and key material.
