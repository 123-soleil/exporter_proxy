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
  `max_concurrent_requests` limit per listener (default 10, extra requests
  get `503`), with sample count, in-flight and rejection metrics.
- Design: absolute, clean paths enforced for `file` and `unix_socket`;
  mandatory `max_age` for file routes with `stale` rejection and a file
  modification time metric.
- Design: `--version` flag and `exporter_proxy_build_info` metric.
- Design: `exporter_proxy_config_hash` metric (SHA-256 of the loaded
  configuration file, first 48 bits).
- `.gitignore` for Go builds, local configuration and key material.
