package config

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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

	if t := fc.TLSCacheTTL; t != nil && (*t < 0 || *t > MaxTLSCacheTTL) {
		v.addf("tls_cache_ttl", "must be between 0 (no cache) and %s", MaxTLSCacheTTL)
	}

	// metrics section: mandatory.
	v.checkListen("metrics", fc.Metrics.Listen, listens)
	v.checkWebConfigFile("metrics", fc.Metrics.WebConfigFile)
	v.checkNetworks("metrics", fc.Metrics.AllowedNetworks)
	if fc.Metrics.ClientCRLFile != "" {
		v.checkAbsPath("metrics", "client_crl_file", fc.Metrics.ClientCRLFile)
	}
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
		if l.ClientCRLFile != "" {
			v.checkAbsPath(where, "client_crl_file", l.ClientCRLFile)
		}

		if len(l.Routes) == 0 {
			v.addf(where, "at least one route is required")
		}
		// The listener's limit, as resolved: a route cannot exceed it.
		listenerMax := valueOr(l.MaxConcurrentRequests, valueOr(fc.Defaults.MaxConcurrentRequests, DefaultMaxConcurrentRequests))
		paths := map[string]bool{}
		for j, r := range l.Routes {
			rwhere := fmt.Sprintf("%s routes[%d]", where, j)
			if r.Path != "" {
				rwhere = fmt.Sprintf("%s route %q", where, r.Path)
			}
			v.checkRoute(rwhere, r)
			v.checkPositiveInt(rwhere, "max_concurrent_requests", r.MaxConcurrentRequests)
			if n := r.MaxConcurrentRequests; n != nil && *n > listenerMax {
				v.addf(rwhere, "max_concurrent_requests (%d) is above the listener's (%d): it would have no effect", *n, listenerMax)
			}
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
	v.checkForwardParams(where, r)
	v.checkCacheTTL(where, r)
	v.checkMetricsFilter(where, r.MetricsFilter)
}

// checkMetricsFilter requires patterns, each valid on its own (so that it
// cannot close the anchoring group) and once anchored.
func (v *validator) checkMetricsFilter(where string, f *fileMetricsFilter) {
	if f == nil {
		return
	}
	if len(f.Allow) == 0 && len(f.Deny) == 0 {
		v.addf(where, "metrics_filter must list allow or deny patterns")
	}
	for _, list := range []struct {
		key      string
		patterns []string
	}{{"allow", f.Allow}, {"deny", f.Deny}} {
		for _, pat := range list.patterns {
			if _, err := regexp.Compile(pat); err != nil {
				v.addf(where, "metrics_filter %s: invalid pattern %q: %v", list.key, pat, err)
			} else if _, err := regexp.Compile(AnchorPattern(pat)); err != nil {
				v.addf(where, "metrics_filter %s: invalid pattern %q: %v", list.key, pat, err)
			}
		}
	}
}

// checkCacheTTL allows a cache on upstream routes only, without
// forward_params (unbounded keys; probes must be live), bounded by
// MaxCacheTTL.
func (v *validator) checkCacheTTL(where string, r fileRoute) {
	if r.CacheTTL == nil {
		return
	}
	switch {
	case *r.CacheTTL <= 0:
		v.addf(where, "cache_ttl must be greater than 0")
	case *r.CacheTTL > MaxCacheTTL:
		v.addf(where, "cache_ttl must be at most %s", MaxCacheTTL)
	case r.Upstream == "":
		v.addf(where, "cache_ttl requires an upstream (files are read without cost)")
	case r.ForwardParams != nil:
		v.addf(where, "cache_ttl and forward_params are mutually exclusive (probes must be live)")
	}
}

// paramNamePattern restricts forwarded query parameter names.
var paramNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// checkForwardParams checks forward_params: HTTP upstreams only, each
// parameter restricted to listed values or patterns, never one the
// upstream URL already sets.
func (v *validator) checkForwardParams(where string, r fileRoute) {
	if r.ForwardParams == nil {
		return
	}
	if len(r.ForwardParams) == 0 {
		v.addf(where, "forward_params is empty: remove it or list the parameters")
		return
	}
	if r.Upstream == "" {
		v.addf(where, "forward_params requires an upstream (not a file route)")
		return
	}
	var fixed url.Values
	if u, err := url.Parse(r.Upstream); err == nil {
		// Forwarded parameters are appended to this query as written:
		// every parameter in it must be seen to be protected.
		if fixed, err = url.ParseQuery(u.RawQuery); err != nil {
			v.addf(where, "forward_params: the upstream URL query cannot be parsed (%v): write it as name=value pairs joined by '&'", err)
			return
		}
	}
	for _, name := range slices.Sorted(maps.Keys(r.ForwardParams)) {
		p := r.ForwardParams[name]
		pw := fmt.Sprintf("forward_params %q", name)
		switch {
		case !paramNamePattern.MatchString(name):
			v.addf(where, "%s: name must only contain letters, digits, '_', '.' and '-'", pw)
		case fixed.Has(name):
			v.addf(where, "%s: already set in the upstream URL", pw)
		}
		if len(p.Values) == 0 && len(p.Patterns) == 0 {
			v.addf(where, "%s: list the allowed values or patterns (any value would be forwarded)", pw)
		}
		for _, val := range p.Values {
			if val == "" || len(val) > MaxParamValueLength {
				v.addf(where, "%s: values must be non-empty and at most %d bytes", pw, MaxParamValueLength)
				break
			}
		}
		for _, pat := range p.Patterns {
			// The pattern must be valid on its own: one closing the
			// anchoring group early ("a)|(.*") would match anything once
			// wrapped.
			if _, err := regexp.Compile(pat); err != nil {
				v.addf(where, "%s: invalid pattern %q: %v", pw, pat, err)
			} else if _, err := regexp.Compile(AnchorPattern(pat)); err != nil {
				v.addf(where, "%s: invalid pattern %q: %v", pw, pat, err)
			}
		}
	}
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
	// Credentials are refused, also when url.Parse would not see them:
	// any '@' in the authority (between "//" and the first '/', '?' or
	// '#'). A '@' in the path or query is allowed.
	if strings.Contains(authority(raw), "@") {
		v.addf(where, "upstream must not contain credentials")
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Parse errors quote parts of the URL: say nothing about it.
		v.addf(where, "upstream is not a valid URL")
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

// authority returns the authority of a URL as written: after "//", up to
// the first '/', '?' or '#'. Empty when there is no "//".
func authority(raw string) string {
	_, rest, ok := strings.Cut(raw, "//")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// MetricsListenerName names the metrics endpoint in logs; listeners cannot
// use it.
const MetricsListenerName = "metrics"

// systemdPrefix marks a listen value taken from systemd socket activation.
const systemdPrefix = "systemd:"

// LoopbackListen reports a "host:port" listen value bound to a loopback
// address only (127.0.0.0/8, ::1 or localhost): reachable from this host
// only. An empty host, a wildcard or a systemd socket is not.
func LoopbackListen(listen string) bool {
	if _, ok := SystemdSocketName(listen); ok {
		return false
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

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
