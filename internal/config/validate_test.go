package config

import (
	"errors"
	"strings"
	"testing"
)

const validMetrics = `
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/ep/web-metrics.yml
`

// withListeners returns a configuration with a valid metrics section and the
// given listeners block (items indented by two spaces).
func withListeners(listeners string) string {
	return validMetrics + "listeners:\n" + listeners
}

// withRoutes returns a configuration with one valid listener holding the
// given routes block (items indented by six spaces).
func withRoutes(routes string) string {
	return withListeners(`  - name: a
    listen: ":9100"
    web_config_file: /etc/ep/web.yml
    routes:
` + routes)
}

const okRoute = `      - path: /metrics
        upstream: http://127.0.0.1:19100/metrics
`

func TestValidateAcceptsValidConfigs(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"http upstream", withRoutes(okRoute)},
		{"upstream with query", withRoutes("      - path: /m\n        upstream: http://127.0.0.1:9187/metrics?collect=x\n")},
		{"unix socket", withRoutes("      - path: /m\n        upstream: http://localhost/metrics\n        unix_socket: /run/app/metrics.sock\n")},
		{"file", withRoutes("      - path: /m\n        file: /var/lib/batch/metrics.prom\n        max_age: 15m\n")},
		{"root path", withRoutes("      - path: /\n        upstream: http://127.0.0.1:19100/metrics\n")},
		{"same path on two listeners", withListeners(`  - name: a
    listen: ":9100"
    web_config_file: /etc/ep/web.yml
    routes:
` + okRoute + `  - name: b
    listen: ":9101"
    web_config_file: /etc/ep/web.yml
    routes:
` + okRoute)},
		{"systemd socket", withListeners("  - name: a\n    listen: \"systemd:node\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute)},
		{"ipv6 listen", withListeners("  - name: a\n    listen: \"[::1]:9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute)},
		{"positive overrides", withRoutes("      - path: /m\n        upstream: http://h/m\n        timeout: 1ms\n        max_body_bytes: 1\n        max_samples: 1\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.yaml)); err != nil {
				t.Errorf("Parse: %v", err)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		// metrics section
		{
			name:    "metrics missing",
			yaml:    "listeners:\n  - name: a\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute,
			wantErr: "metrics: listen is required",
		},
		{
			name:    "metrics without web config",
			yaml:    "metrics:\n  listen: \":9999\"\nlisteners:\n  - name: a\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute,
			wantErr: "metrics: web_config_file is required",
		},

		// listeners
		{
			name:    "no listener",
			yaml:    validMetrics + "listeners: []\n",
			wantErr: "at least one listener is required",
		},
		{
			name:    "listener without name",
			yaml:    withListeners("  - listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "listeners[0]: name is required",
		},
		{
			name:    "listener name with space",
			yaml:    withListeners("  - name: my node\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "name must only contain",
		},
		{
			name: "duplicate listener name",
			yaml: withListeners("  - name: a\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute +
				"  - name: a\n    listen: \":9101\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: `listener "a": duplicate listener name`,
		},
		{
			name:    "reserved listener name",
			yaml:    withListeners("  - name: metrics\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: `name "metrics" is reserved for the metrics endpoint`,
		},
		{
			name:    "listener without listen",
			yaml:    withListeners("  - name: a\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: `listener "a": listen is required`,
		},
		{
			name:    "listen without port",
			yaml:    withListeners("  - name: a\n    listen: \"127.0.0.1\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "is not host:port",
		},
		{
			name:    "listen port out of range",
			yaml:    withListeners("  - name: a\n    listen: \":70000\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "empty systemd socket name",
			yaml:    withListeners("  - name: a\n    listen: \"systemd:\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "systemd socket name must only contain",
		},
		{
			name:    "invalid systemd socket name",
			yaml:    withListeners("  - name: a\n    listen: \"systemd:my socket\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "systemd socket name must only contain",
		},
		{
			name: "same systemd socket twice",
			yaml: withListeners("  - name: a\n    listen: \"systemd:s\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute +
				"  - name: b\n    listen: \"systemd:s\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: `listen "systemd:s" is already used by listener "a"`,
		},
		{
			name:    "listen address shared with metrics",
			yaml:    withListeners("  - name: a\n    listen: \"127.0.0.1:9999\"\n    web_config_file: /etc/ep/web.yml\n    routes:\n" + okRoute),
			wantErr: "is already used by metrics",
		},
		{
			name:    "listener without web config",
			yaml:    withListeners("  - name: a\n    listen: \":9100\"\n    routes:\n" + okRoute),
			wantErr: `listener "a": web_config_file is required`,
		},
		{
			name:    "relative web config",
			yaml:    withListeners("  - name: a\n    listen: \":9100\"\n    web_config_file: web.yml\n    routes:\n" + okRoute),
			wantErr: "web_config_file must be an absolute path",
		},
		{
			name:    "listener without route",
			yaml:    withListeners("  - name: a\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n"),
			wantErr: "at least one route is required",
		},

		// route paths
		{
			name:    "route without path",
			yaml:    withRoutes("      - upstream: http://h/m\n"),
			wantErr: "routes[0]: path is required",
		},
		{
			name:    "path without leading slash",
			yaml:    withRoutes("      - path: metrics\n        upstream: http://h/m\n"),
			wantErr: "path must start with '/'",
		},
		{
			name:    "path with dot-dot",
			yaml:    withRoutes("      - path: /a/../metrics\n        upstream: http://h/m\n"),
			wantErr: `path must be clean (no '.', '..', '//' or trailing '/'), use "/metrics"`,
		},
		{
			name:    "path with trailing slash",
			yaml:    withRoutes("      - path: /metrics/\n        upstream: http://h/m\n"),
			wantErr: "path must be clean",
		},
		{
			name:    "path with query",
			yaml:    withRoutes("      - path: /metrics?x=1\n        upstream: http://h/m\n"),
			wantErr: "must not contain a query or fragment",
		},
		{
			name:    "duplicate path in listener",
			yaml:    withRoutes(okRoute + okRoute),
			wantErr: `route "/metrics": duplicate path in this listener`,
		},

		// sources
		{
			name:    "no source",
			yaml:    withRoutes("      - path: /m\n"),
			wantErr: "one source is required: upstream or file",
		},
		{
			name:    "upstream and file",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        file: /var/lib/x.prom\n        max_age: 1m\n"),
			wantErr: "upstream and file are mutually exclusive",
		},
		{
			name:    "unix socket without upstream",
			yaml:    withRoutes("      - path: /m\n        unix_socket: /run/app.sock\n"),
			wantErr: "unix_socket requires upstream",
		},
		{
			name:    "unix socket with file",
			yaml:    withRoutes("      - path: /m\n        file: /var/lib/x.prom\n        max_age: 1m\n        unix_socket: /run/app.sock\n"),
			wantErr: "unix_socket requires upstream",
		},
		{
			name:    "unsupported upstream scheme",
			yaml:    withRoutes("      - path: /m\n        upstream: ftp://h/m\n"),
			wantErr: `upstream must use http:// or https:// (got "ftp")`,
		},
		{
			name:    "upstream without scheme",
			yaml:    withRoutes("      - path: /m\n        upstream: 127.0.0.1:9100/metrics\n"),
			wantErr: "upstream",
		},
		{
			name:    "upstream without host",
			yaml:    withRoutes("      - path: /m\n        upstream: http:///metrics\n"),
			wantErr: "upstream must have a host",
		},
		{
			name:    "upstream with credentials",
			yaml:    withRoutes("      - path: /m\n        upstream: http://user:CHANGE_ME@h/m\n"),
			wantErr: "upstream must not contain credentials",
		},
		{
			name:    "upstream with fragment",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m#x\n"),
			wantErr: "upstream must not contain a fragment",
		},

		// absolute and clean paths
		{
			name:    "relative file",
			yaml:    withRoutes("      - path: /m\n        file: metrics.prom\n        max_age: 1m\n"),
			wantErr: "file must be an absolute path",
		},
		{
			name:    "file with dot-dot",
			yaml:    withRoutes("      - path: /m\n        file: /var/lib/../../etc/shadow\n        max_age: 1m\n"),
			wantErr: `file must be a clean path (no '.', '..', '//' or trailing '/'), use "/etc/shadow"`,
		},
		{
			name:    "file with double slash",
			yaml:    withRoutes("      - path: /m\n        file: /var/lib//x.prom\n        max_age: 1m\n"),
			wantErr: "file must be a clean path",
		},
		{
			name:    "relative unix socket",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        unix_socket: run/app.sock\n"),
			wantErr: "unix_socket must be an absolute path",
		},
		{
			name:    "unix socket with dot",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        unix_socket: /run/./app.sock\n"),
			wantErr: "unix_socket must be a clean path",
		},

		// max_age
		{
			name:    "file without max_age",
			yaml:    withRoutes("      - path: /m\n        file: /var/lib/x.prom\n"),
			wantErr: "max_age is required for file routes",
		},
		{
			name:    "max_age on upstream route",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        max_age: 1m\n"),
			wantErr: "max_age is only valid for file routes",
		},
		{
			name:    "zero max_age",
			yaml:    withRoutes("      - path: /m\n        file: /var/lib/x.prom\n        max_age: 0s\n"),
			wantErr: "max_age must be greater than 0",
		},

		// limits
		{
			name:    "zero timeout in defaults",
			yaml:    withRoutes(okRoute) + "defaults:\n  timeout: 0s\n",
			wantErr: "defaults: timeout must be greater than 0",
		},
		{
			name:    "negative timeout on route",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        timeout: -1s\n"),
			wantErr: `route "/m": timeout must be greater than 0`,
		},
		{
			name:    "zero max_body_bytes in defaults",
			yaml:    withRoutes(okRoute) + "defaults:\n  max_body_bytes: 0\n",
			wantErr: "defaults: max_body_bytes must be greater than 0",
		},
		{
			name:    "negative max_body_bytes on route",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        max_body_bytes: -5\n"),
			wantErr: "max_body_bytes must be greater than 0",
		},
		{
			name:    "huge max_body_bytes on route",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        max_body_bytes: 9223372036854775807\n"),
			wantErr: "max_body_bytes must be at most 1073741824 (1 GiB)",
		},
		{
			name:    "zero max_samples on route",
			yaml:    withRoutes("      - path: /m\n        upstream: http://h/m\n        max_samples: 0\n"),
			wantErr: "max_samples must be greater than 0",
		},
		{
			name:    "zero max_concurrent_requests in defaults",
			yaml:    withRoutes(okRoute) + "defaults:\n  max_concurrent_requests: 0\n",
			wantErr: "defaults: max_concurrent_requests must be greater than 0",
		},
		{
			name:    "negative max_concurrent_requests on listener",
			yaml:    withListeners("  - name: a\n    listen: \":9100\"\n    web_config_file: /etc/ep/web.yml\n    max_concurrent_requests: -1\n    routes:\n" + okRoute),
			wantErr: `listener "a": max_concurrent_requests must be greater than 0`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q\nwant substring %q", err, tt.wantErr)
			}
			if strings.ContainsAny(err.Error(), "\r\n") {
				t.Errorf("error spans several lines: %q", err)
			}
		})
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	yaml := withListeners(`  - name: a
    listen: ":9100"
    routes:
      - path: metrics
        upstream: ftp://h/m
      - path: /f
        file: relative.prom
`)
	_, err := Parse([]byte(yaml))

	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("error = %v, want *ValidationError", err)
	}
	want := []string{
		"web_config_file is required",
		"path must start with '/'",
		"upstream must use http:// or https://",
		"file must be an absolute path",
		"max_age is required for file routes",
	}
	if len(verr.Problems) != len(want) {
		t.Errorf("got %d problems, want %d: %q", len(verr.Problems), len(want), verr.Problems)
	}
	for _, w := range want {
		found := false
		for _, p := range verr.Problems {
			if strings.Contains(p, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing problem %q in %q", w, verr.Problems)
		}
	}
}

func TestHash(t *testing.T) {
	base := withRoutes(okRoute)
	parse := func(s string) *Config {
		t.Helper()
		cfg, err := Parse([]byte(s))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return cfg
	}

	a := parse(base)
	if a.Hash >= 1<<48 {
		t.Errorf("hash %x exceeds 48 bits", a.Hash)
	}
	if uint64(float64(a.Hash)) != a.Hash {
		t.Errorf("hash %d is not exact as float64", a.Hash)
	}
	if b := parse(base); b.Hash != a.Hash {
		t.Errorf("same content, different hashes: %x vs %x", a.Hash, b.Hash)
	}
	if c := parse(base + "# comment\n"); c.Hash == a.Hash {
		t.Error("adding a comment did not change the hash")
	}
	if got := a.HashString(); len(got) != 12 {
		t.Errorf("HashString() = %q, want 12 hex digits", got)
	}

	// Known value: SHA-256("") starts with e3b0c44298fc.
	if got := hash48(nil); got != 0xe3b0c44298fc {
		t.Errorf("hash48(empty) = %x, want e3b0c44298fc", got)
	}
}
