package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fullConfig = `
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/exporter_proxy/web-metrics.yml

defaults:
  timeout: 5s
  max_body_bytes: 1048576
  max_samples: 1000
  max_concurrent_requests: 4

listeners:
  - name: node
    listen: ":9100"
    web_config_file: /etc/exporter_proxy/web-mtls.yml
    routes:
      - path: /metrics
        upstream: http://127.0.0.1:19100/metrics

  - name: shared
    listen: ":9443"
    web_config_file: /etc/exporter_proxy/web-basic.yml
    max_concurrent_requests: 2
    routes:
      - path: /postgres/metrics
        upstream: http://127.0.0.1:19187/metrics
        timeout: 20s
        max_body_bytes: 2097152
        max_samples: 3000
      - path: /app/metrics
        upstream: http://localhost/metrics
        unix_socket: /run/app/metrics.sock
      - path: /batch/metrics
        file: /var/lib/batch/metrics.prom
        max_age: 15m
`

func TestParseResolvesDefaultsAndOverrides(t *testing.T) {
	cfg, err := Parse([]byte(fullConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	defaults := Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1048576, MaxSamples: 1000}
	want := &Config{
		Metrics: MetricsEndpoint{
			Listen:        "127.0.0.1:9999",
			WebConfigFile: "/etc/exporter_proxy/web-metrics.yml",
		},
		Listeners: []Listener{
			{
				Name:                  "node",
				Listen:                ":9100",
				WebConfigFile:         "/etc/exporter_proxy/web-mtls.yml",
				MaxConcurrentRequests: 4, // from defaults section
				Routes: []Route{
					{Path: "/metrics", Upstream: "http://127.0.0.1:19100/metrics", Limits: defaults},
				},
			},
			{
				Name:                  "shared",
				Listen:                ":9443",
				WebConfigFile:         "/etc/exporter_proxy/web-basic.yml",
				MaxConcurrentRequests: 2, // listener override
				Routes: []Route{
					{
						Path:     "/postgres/metrics",
						Upstream: "http://127.0.0.1:19187/metrics",
						Limits:   Limits{Timeout: 20 * time.Second, MaxBodyBytes: 2097152, MaxSamples: 3000},
					},
					{
						Path:       "/app/metrics",
						Upstream:   "http://localhost/metrics",
						UnixSocket: "/run/app/metrics.sock",
						Limits:     defaults,
					},
					{
						Path:   "/batch/metrics",
						File:   "/var/lib/batch/metrics.prom",
						MaxAge: 15 * time.Minute,
						Limits: defaults,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("resolved config mismatch\n got: %+v\nwant: %+v", cfg, want)
	}
}

func TestParseBuiltinDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
listeners:
  - name: node
    listen: ":9100"
    routes:
      - path: /metrics
        upstream: http://127.0.0.1:19100/metrics
      - path: /slow
        upstream: http://127.0.0.1:19101/metrics
        timeout: 30s
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	l := cfg.Listeners[0]
	if l.MaxConcurrentRequests != DefaultMaxConcurrentRequests {
		t.Errorf("MaxConcurrentRequests = %d, want %d", l.MaxConcurrentRequests, DefaultMaxConcurrentRequests)
	}
	builtin := Limits{Timeout: DefaultTimeout, MaxBodyBytes: DefaultMaxBodyBytes, MaxSamples: DefaultMaxSamples}
	if got := l.Routes[0].Limits; got != builtin {
		t.Errorf("route without overrides: limits = %+v, want %+v", got, builtin)
	}
	partial := builtin
	partial.Timeout = 30 * time.Second
	if got := l.Routes[1].Limits; got != partial {
		t.Errorf("route with timeout override: limits = %+v, want %+v", got, partial)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty document",
			yaml:    "",
			wantErr: "empty configuration",
		},
		{
			name:    "unknown top-level key",
			yaml:    "listners: []\n",
			wantErr: "field listners not found",
		},
		{
			name:    "unknown key in defaults",
			yaml:    "defaults:\n  timeot: 5s\n",
			wantErr: "field timeot not found",
		},
		{
			name:    "unknown key in metrics",
			yaml:    "metrics:\n  address: x\n",
			wantErr: "field address not found",
		},
		{
			name:    "unknown key in listener",
			yaml:    "listeners:\n  - name: a\n    tls: true\n",
			wantErr: "field tls not found",
		},
		{
			name:    "unknown key in route",
			yaml:    "listeners:\n  - name: a\n    routes:\n      - path: /m\n        upstreem: http://x\n",
			wantErr: "field upstreem not found",
		},
		{
			name:    "max_concurrent_requests is not a route key",
			yaml:    "listeners:\n  - name: a\n    routes:\n      - path: /m\n        max_concurrent_requests: 3\n",
			wantErr: "field max_concurrent_requests not found",
		},
		{
			name:    "invalid duration",
			yaml:    "defaults:\n  timeout: ten seconds\n",
			wantErr: "line 2: cannot unmarshal !!str",
		},
		{
			name:    "duration without unit",
			yaml:    "defaults:\n  timeout: 10\n",
			wantErr: "cannot unmarshal",
		},
		{
			name:    "wrong type",
			yaml:    "defaults:\n  max_samples: lots\n",
			wantErr: "cannot unmarshal",
		},
		{
			name:    "several documents",
			yaml:    "listeners: []\n---\nlisteners: []\n",
			wantErr: "single YAML document",
		},
		{
			name:    "invalid YAML",
			yaml:    "listeners: [\n",
			wantErr: "yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
			if strings.ContainsAny(err.Error(), "\r\n") {
				t.Errorf("error spans several lines: %q", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(good, []byte(fullConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(good); err != nil {
		t.Errorf("Load(valid file): %v", err)
	}

	bad := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(bad, []byte("nope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("Load(invalid file) error = %v, want it to name the file", err)
	}

	if _, err := Load(filepath.Join(dir, "missing.yml")); err == nil {
		t.Error("Load(missing file) succeeded, want error")
	}
}
