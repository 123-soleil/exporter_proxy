// Package check verifies a whole setup without starting anything: the web
// configuration files and the TLS material they reference, the metrics files
// and the Unix sockets of the routes.
//
// It does not contact HTTP upstreams over TCP. Permissions are those of the
// user running the check: run it as the service user.
package check

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/prometheus/exporter-toolkit/web"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/errfmt"
	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// expiryWarning is how long before expiry a certificate gets a warning.
const expiryWarning = 30 * 24 * time.Hour

// Severity of a finding.
type Severity string

// Severities.
const (
	Problem Severity = "problem" // the setup does not work as configured
	Warning Severity = "warning" // works, but needs attention
)

// Finding is one result of the check.
type Finding struct {
	Severity Severity
	Where    string // e.g. `listener "node" route "/metrics"`
	Message  string
}

// Run checks cfg (already loaded and validated) at time now.
func Run(cfg *config.Config, now time.Time) []Finding {
	c := &checker{now: now}

	c.webConfig("metrics", cfg.Metrics.WebConfigFile)
	for _, l := range cfg.Listeners {
		where := fmt.Sprintf("listener %q", l.Name)
		c.webConfig(where, l.WebConfigFile)
		for _, r := range l.Routes {
			rwhere := fmt.Sprintf("%s route %q", where, r.Path)
			switch {
			case r.File != "":
				c.metricsFile(rwhere, r.File, r.MaxAge)
			case r.UnixSocket != "":
				c.socket(rwhere, r.UnixSocket)
			}
		}
	}
	return c.findings
}

type checker struct {
	now      time.Time
	findings []Finding
	seen     map[string]bool // web configuration files already checked
}

func (c *checker) add(sev Severity, where, format string, args ...any) {
	c.findings = append(c.findings, Finding{Severity: sev, Where: where, Message: fmt.Sprintf(format, args...)})
}

// webConfig checks a web configuration file once, even if shared.
func (c *checker) webConfig(where, path string) {
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[path] {
		return
	}
	c.seen[path] = true
	where = fmt.Sprintf("%s web_config_file %s", where, path)

	// exporter-toolkit's own validation: strict YAML, bcrypt hashes,
	// certificate and key readable and matching, client CA readable.
	if err := web.Validate(path); err != nil {
		c.add(Problem, where, "%s", errfmt.OneLine(err))
		return
	}
	wc, err := webconfig.Read(path)
	if err != nil {
		c.add(Problem, where, "%s", errfmt.OneLine(err))
		return
	}
	if wc.BasicAuthWithoutTLS() {
		c.add(Warning, where, "basic authentication without TLS: credentials travel in clear text")
	}
	switch {
	case wc.CertFile != "":
		c.certificates(where, "cert_file", wc.CertFile, false)
	case wc.CertPEM != "":
		c.certificatesPEM(where, "cert (inline)", []byte(wc.CertPEM), false)
	}
	switch {
	case wc.ClientCAFile != "":
		c.certificates(where, "client_ca_file", wc.ClientCAFile, true)
	case wc.ClientCAPEM != "":
		c.certificatesPEM(where, "client_ca (inline)", []byte(wc.ClientCAPEM), true)
	}
}

// certificates checks the validity dates of the certificates in a PEM file.
func (c *checker) certificates(where, key, path string, bundle bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		c.add(Problem, where, "%s: %v", key, err)
		return
	}
	c.certificatesPEM(where, key+" "+path, data, bundle)
}

// certificatesPEM checks the validity dates of PEM certificates.
//
// For a server certificate, the leaf must be within its dates (a problem
// otherwise; unparseable, it stops the check); intermediates outside their
// dates are warnings, since clients usually build another path around an
// expired cross-signature. A client CA bundle is judged like crypto/tls
// uses it: certificates it cannot use (unparseable, expired, not valid yet)
// are only warnings, normal while rotating CAs, as long as one certificate
// is currently valid.
func (c *checker) certificatesPEM(where, label string, data []byte, bundle bool) {
	issue := Problem
	if bundle {
		issue = Warning
	}
	n, valid := 0, 0 // n: certificates seen, parsed or not
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		if !bundle && n == 2 {
			// Intermediates: an expired one (an old cross-signature) is
			// skipped by clients building another path, so only a warning.
			issue = Warning
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c.add(issue, where, "%s: certificate %d: %v", label, n, err)
			if !bundle {
				return // the leaf certificate is unusable: the next ones are not leaves
			}
			continue
		}
		subject := cert.Subject.String()
		switch {
		case c.now.After(cert.NotAfter):
			c.add(issue, where, "%s: certificate %q expired on %s", label, subject, cert.NotAfter.UTC().Format(time.RFC3339))
		case c.now.Before(cert.NotBefore):
			c.add(issue, where, "%s: certificate %q is not valid before %s", label, subject, cert.NotBefore.UTC().Format(time.RFC3339))
		default:
			valid++
			if cert.NotAfter.Sub(c.now) < expiryWarning {
				c.add(Warning, where, "%s: certificate %q expires on %s", label, subject, cert.NotAfter.UTC().Format(time.RFC3339))
			}
		}
	}
	if bundle && valid == 0 {
		c.add(Problem, where, "%s: no currently valid certificate", label)
	}
}

// metricsFile checks a file route the way the proxy reads it.
func (c *checker) metricsFile(where, path string, maxAge time.Duration) {
	// O_NONBLOCK: a FIFO must not block the check.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		c.add(Problem, where, "file: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		c.add(Problem, where, "file: %v", err)
		return
	}
	if !info.Mode().IsRegular() {
		c.add(Problem, where, "file %s is not a regular file (%s)", path, info.Mode().Type())
		return
	}
	switch age := c.now.Sub(info.ModTime()); {
	case age > maxAge:
		c.add(Problem, where, "file %s was modified %s ago, more than max_age (%s)", path, age.Truncate(time.Second), maxAge)
	case -age > maxAge:
		c.add(Problem, where, "file %s was modified %s in the future, more than max_age (%s): clock skew?",
			path, (-age).Truncate(time.Second), maxAge)
	}
}

// socket checks that a Unix socket exists and can be connected to:
// connect() requires write permission on the socket file.
func (c *checker) socket(where, path string) {
	info, err := os.Stat(path)
	if err != nil {
		c.add(Problem, where, "unix_socket: %v", err)
		return
	}
	if info.Mode().Type() != os.ModeSocket {
		c.add(Problem, where, "unix_socket %s is not a socket (%s)", path, info.Mode().Type())
		return
	}
	// access(2) checks with the real user ID: right when run as the
	// service user (sudo -u exporter_proxy ...).
	if err := syscall.Access(path, 2 /* W_OK */); err != nil {
		c.add(Problem, where, "unix_socket %s is not writable by this user: %v", path, err)
	}
}
