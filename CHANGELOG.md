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
- Listeners served with exporter-toolkit (TLS, mTLS, basic auth from the web
  configuration file, re-read while running): web configurations validated
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
- `.gitignore` for Go builds, local configuration and key material.
