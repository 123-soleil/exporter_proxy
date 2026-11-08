package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationError lists every problem found in a configuration, so that an
// administrator can fix them all at once instead of one per restart.
type ValidationError struct {
	Problems []string
}

// Error returns all problems on a single line (one log event per line).
func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid configuration: %s", strings.Join(e.Problems, "; "))
}

// namePattern restricts listener names, which are used as metric label
// values and in logs.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validator accumulates problems with their location in the file.
type validator struct {
	problems []string
}

func (v *validator) addf(where, format string, args ...any) {
	v.problems = append(v.problems, where+": "+fmt.Sprintf(format, args...))
}

// validate checks the decoded file before defaults are resolved, so that a
// problem is reported where it is written (defaults section, listener or
// route) and only once.
func validate(fc *fileConfig) error {
	v := &validator{}

	listens := map[string]string{} // listen address -> where it is used

	// metrics section: mandatory.
	v.checkListen("metrics", fc.Metrics.Listen, listens)
	v.checkWebConfigFile("metrics", fc.Metrics.WebConfigFile)
	v.checkNetworks("metrics", fc.Metrics.AllowedNetworks)
	v.checkServiceDiscovery(fc.Metrics.ServiceDiscovery)

	// defaults section: every value set must be positive.
	v.checkLimits("defaults", fc.Defaults.fileLimits)
	v.checkPositiveInt("defaults", "max_concurrent_requests", fc.Defaults.MaxConcurrentRequests)

	if len(fc.Listeners) == 0 {
		v.addf("listeners", "at least one listener is required")
	}
	names := map[string]bool{}
	for i, l := range fc.Listeners {
		where := fmt.Sprintf("listeners[%d]", i)
		if l.Name != "" {
			where = fmt.Sprintf("listener %q", l.Name)
		}

		switch {
		case l.Name == "":
			v.addf(where, "name is required")
		case !namePattern.MatchString(l.Name):
			v.addf(where, "name must only contain letters, digits, '_', '.' and '-'")
		case names[l.Name]:
			v.addf(where, "duplicate listener name")
		case l.Name == MetricsListenerName:
			v.addf(where, "name %q is reserved for the metrics endpoint", MetricsListenerName)
		}
		names[l.Name] = true

		v.checkListen(where, l.Listen, listens)
		v.checkWebConfigFile(where, l.WebConfigFile)
		v.checkPositiveInt(where, "max_concurrent_requests", l.MaxConcurrentRequests)
		v.checkNetworks(where, l.AllowedNetworks)

		if len(l.Routes) == 0 {
			v.addf(where, "at least one route is required")
		}
		paths := map[string]bool{}
		for j, r := range l.Routes {
			rwhere := fmt.Sprintf("%s routes[%d]", where, j)
			if r.Path != "" {
				rwhere = fmt.Sprintf("%s route %q", where, r.Path)
			}
			v.checkRoute(rwhere, r)
			if r.Path != "" && paths[r.Path] {
				v.addf(rwhere, "duplicate path in this listener")
			}
			paths[r.Path] = true
		}
	}

	if len(v.problems) > 0 {
		return &ValidationError{Problems: v.problems}
	}
	return nil
}

func (v *validator) checkRoute(where string, r fileRoute) {
	switch {
	case r.Path == "":
		v.addf(where, "path is required")
	case !strings.HasPrefix(r.Path, "/"):
		v.addf(where, "path must start with '/'")
	case strings.ContainsAny(r.Path, "?#"):
		v.addf(where, "path must not contain a query or fragment")
	case path.Clean(r.Path) != r.Path:
		v.addf(where, "path must be clean (no '.', '..', '//' or trailing '/'), use %q", path.Clean(r.Path))
	}

	// Exactly one source: upstream (optionally over unix_socket) or file.
	hasUpstream, hasFile := r.Upstream != "", r.File != ""
	switch {
	case hasUpstream && hasFile:
		v.addf(where, "upstream and file are mutually exclusive")
	case !hasUpstream && !hasFile:
		v.addf(where, "one source is required: upstream or file")
	}
	if r.UnixSocket != "" && !hasUpstream {
		v.addf(where, "unix_socket requires upstream (HTTP over the socket)")
	}

	if hasUpstream {
		v.checkUpstream(where, r.Upstream)
	}
	https := strings.HasPrefix(r.Upstream, "https://")
	if https && r.UnixSocket != "" {
		v.addf(where, "unix_socket requires an http:// upstream")
	}
	if t := r.UpstreamTLS; t != nil {
		if !https {
			v.addf(where, "upstream_tls requires an https:// upstream")
		}
		if (t.CertFile == "") != (t.KeyFile == "") {
			v.addf(where, "upstream_tls: cert_file and key_file go together")
		}
		for _, f := range []struct{ key, path string }{
			{"upstream_tls ca_file", t.CAFile}, {"upstream_tls cert_file", t.CertFile}, {"upstream_tls key_file", t.KeyFile},
		} {
			if f.path != "" {
				v.checkAbsPath(where, f.key, f.path)
			}
		}
		if *t == (fileUpstreamTLS{}) {
			v.addf(where, "upstream_tls is empty: remove it (the system roots verify the upstream) or set its fields")
		}
	}
	if r.UnixSocket != "" {
		v.checkAbsPath(where, "unix_socket", r.UnixSocket)
	}
	if hasFile {
		v.checkAbsPath(where, "file", r.File)
		if r.MaxAge == nil {
			v.addf(where, "max_age is required for file routes")
		}
	} else if r.MaxAge != nil {
		v.addf(where, "max_age is only valid for file routes")
	}
	v.checkPositiveDuration(where, "max_age", r.MaxAge)

	v.checkLimits(where, r.fileLimits)
	v.checkAuthorize(where, r.Authorize)
}

// checkAuthorize rejects an authorize block that would refuse every
// request, or that holds empty names.
func (v *validator) checkAuthorize(where string, a *fileAuthorize) {
	if a == nil {
		return
	}
	if len(a.Users) == 0 && len(a.ClientSANs) == 0 {
		v.addf(where, "authorize must list users or client_sans (an empty authorize would refuse every request)")
	}
	for _, list := range []struct {
		key   string
		names []string
	}{{"users", a.Users}, {"client_sans", a.ClientSANs}} {
		seen := map[string]bool{}
		for _, n := range list.names {
			switch {
			case strings.TrimSpace(n) == "":
				v.addf(where, "authorize %s: empty name", list.key)
			case seen[n]:
				v.addf(where, "authorize %s: duplicate %q", list.key, n)
			}
			seen[n] = true
		}
	}
}

func (v *validator) checkUpstream(where, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		v.addf(where, "upstream is not a valid URL: %v", err)
		return
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		v.addf(where, "upstream must use http:// or https:// (got %q)", u.Scheme)
	case u.Host == "":
		v.addf(where, "upstream must have a host")
	case u.User != nil:
		// Credentials would end up in logs and in the hashed config.
		v.addf(where, "upstream must not contain credentials")
	case u.Fragment != "":
		v.addf(where, "upstream must not contain a fragment")
	}
}

// MetricsListenerName names the metrics endpoint in logs; listeners cannot
// use it.
const MetricsListenerName = "metrics"

// systemdPrefix marks a listen value taken from systemd socket activation.
const systemdPrefix = "systemd:"

// SystemdSocketName returns the socket name of a "systemd:<name>" listen
// value: the FileDescriptorName= of the socket unit.
func SystemdSocketName(listen string) (string, bool) {
	name, ok := strings.CutPrefix(listen, systemdPrefix)
	return name, ok
}

func (v *validator) checkListen(where, addr string, seen map[string]string) {
	if addr == "" {
		v.addf(where, "listen is required")
		return
	}
	if name, ok := SystemdSocketName(addr); ok {
		if !namePattern.MatchString(name) {
			v.addf(where, "listen %q: systemd socket name must only contain letters, digits, '_', '.' and '-'", addr)
			return
		}
	} else {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			v.addf(where, "listen %q is not host:port or systemd:<name>: %v", addr, err)
			return
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			v.addf(where, "listen %q: port must be between 1 and 65535", addr)
			return
		}
	}
	if other, ok := seen[addr]; ok {
		v.addf(where, "listen %q is already used by %s", addr, other)
		return
	}
	seen[addr] = where
}

// labelNamePattern restricts service discovery label names to classic
// Prometheus label names; names starting with "__" are reserved.
var labelNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// checkServiceDiscovery checks the service_discovery block of metrics.
func (v *validator) checkServiceDiscovery(sd *fileServiceDiscovery) {
	if sd == nil {
		return
	}
	const where = "metrics service_discovery"
	switch {
	case sd.Host == "":
		v.addf(where, "host is required: the name or address Prometheus reaches the listeners at")
	case strings.ContainsAny(sd.Host, "/[]@ ") || strings.Count(sd.Host, ":") == 1:
		v.addf(where, "host %q must be a name or an address, without scheme, port or brackets", sd.Host)
	case strings.Contains(sd.Host, ":"):
		if _, err := netip.ParseAddr(sd.Host); err != nil {
			v.addf(where, "host %q is not a valid IPv6 address", sd.Host)
		}
	}
	for name := range sd.Labels {
		switch {
		case !labelNamePattern.MatchString(name):
			v.addf(where, "label name %q is not a valid Prometheus label name", name)
		case strings.HasPrefix(name, "__"):
			v.addf(where, "label name %q is reserved (names starting with \"__\")", name)
		case name == "exporter_proxy_listener" || name == "exporter_proxy_route":
			v.addf(where, "label name %q is set by exporter_proxy", name)
		}
	}
}

// checkNetworks checks allowed_networks: unset allows every address, an
// empty list would refuse every client.
func (v *validator) checkNetworks(where string, entries []string) {
	if entries == nil {
		return
	}
	if len(entries) == 0 {
		v.addf(where, "allowed_networks is empty: remove it or list the allowed networks")
		return
	}
	for _, e := range entries {
		if _, err := ParseNetwork(e); err != nil {
			v.addf(where, "allowed_networks %q is not an address or a network in CIDR notation: %v", e, err)
		}
	}
}

func (v *validator) checkWebConfigFile(where, p string) {
	if p == "" {
		v.addf(where, "web_config_file is required")
		return
	}
	v.checkAbsPath(where, "web_config_file", p)
}

// checkAbsPath requires an absolute path already in canonical form, so that
// the target never depends on the working directory and is exactly what is
// written in the file.
func (v *validator) checkAbsPath(where, key, p string) {
	switch {
	case !filepath.IsAbs(p):
		v.addf(where, "%s must be an absolute path", key)
	case filepath.Clean(p) != p:
		v.addf(where, "%s must be a clean path (no '.', '..', '//' or trailing '/'), use %q", key, filepath.Clean(p))
	}
}

func (v *validator) checkLimits(where string, l fileLimits) {
	v.checkPositiveDuration(where, "timeout", l.Timeout)
	switch {
	case l.MaxBodyBytes == nil:
	case *l.MaxBodyBytes <= 0:
		v.addf(where, "max_body_bytes must be greater than 0")
	case *l.MaxBodyBytes > MaxMaxBodyBytes:
		v.addf(where, "max_body_bytes must be at most %d (1 GiB)", MaxMaxBodyBytes)
	}
	v.checkPositiveInt(where, "max_samples", l.MaxSamples)
}

func (v *validator) checkPositiveDuration(where, key string, d *time.Duration) {
	if d != nil && *d <= 0 {
		v.addf(where, "%s must be greater than 0", key)
	}
}

func (v *validator) checkPositiveInt(where, key string, n *int) {
	if n != nil && *n <= 0 {
		v.addf(where, "%s must be greater than 0", key)
	}
}
