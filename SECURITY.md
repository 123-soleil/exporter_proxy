# Security policy

exporter_proxy guards access to metrics (TLS, mTLS, basic authentication).
Vulnerabilities in it are taken seriously.

## Supported versions

Only the latest release receives security fixes while the project is in
0.x.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[Report a vulnerability](https://github.com/123-soleil/exporter_proxy/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Please include:

- the version (`exporter_proxy --version`) and the operating system;
- the relevant configuration and web configuration, with secrets removed
  (passwords, bcrypt hashes, private keys);
- the steps to reproduce, and what an attacker gains (authentication
  bypass, denial of service, information disclosure, ...).

You should get a first answer within a week. Once a fix is released, the
advisory is published with credit to the reporter, unless they prefer
otherwise.

## Scope

In scope: authentication bypass (TLS, mTLS, basic auth), configuration
changes that weaken authentication without a restart, request smuggling
toward upstreams, resource exhaustion from a remote client, information
leaks in responses or logs.

Out of scope: vulnerabilities of the upstream exporters themselves, and
setups that ignore the documented requirements (for example basic
authentication without TLS, which `--check` and the logs warn about).

## Verifying a release

Every release archive comes with `sha256sums.txt` and a build provenance
attestation, which proves that the archive was built by this repository's
GitHub Actions from the tagged commit:

```sh
sha256sum -c --ignore-missing sha256sums.txt
gh attestation verify exporter_proxy_<version>_<os>_<arch>.tar.gz --repo 123-soleil/exporter_proxy
```
