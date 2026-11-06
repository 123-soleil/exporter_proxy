package config

import (
	"fmt"
	"net"
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
}

func (v *validator) checkUpstream(where, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		v.addf(where, "upstream is not a valid URL: %v", err)
		return
	}
	switch {
	case u.Scheme != "http":
		v.addf(where, "upstream must use http:// (got %q)", u.Scheme)
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
