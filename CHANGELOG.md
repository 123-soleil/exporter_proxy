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
- Design: `max_samples` limit per response (default 50000) and
  `max_concurrent_requests` limit per listener (default 4, extra requests
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
- Built-in defaults sized from the benchmark: `max_body_bytes` 4 MiB (about
  `max_samples` worth of text) and `max_concurrent_requests` 4, bounding the
  worst-case parsing memory to about 180 MiB per listener.
- `.gitignore` for Go builds, local configuration and key material.
