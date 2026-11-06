package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunExitCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yml")
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring, empty means stdout must be empty
		wantStderr string // substring, empty means not checked
	}{
		{
			name:       "version",
			args:       []string{"--version"},
			wantCode:   exitOK,
			wantStdout: "exporter_proxy version=",
		},
		{
			name:     "help",
			args:     []string{"--help"},
			wantCode: exitOK,
		},
		{
			name:       "unknown flag",
			args:       []string{"--nope"},
			wantCode:   exitUsage,
			wantStderr: "flag provided but not defined",
		},
		{
			name:       "invalid log level",
			args:       []string{"--log.level=verbose"},
			wantCode:   exitUsage,
			wantStderr: "log.level",
		},
		{
			name:       "invalid log format",
			args:       []string{"--log.format=xml"},
			wantCode:   exitUsage,
			wantStderr: "log.format",
		},
		{
			name:       "unexpected positional argument",
			args:       []string{"extra"},
			wantCode:   exitUsage,
			wantStderr: `unexpected argument "extra"`,
		},
		{
			name:       "web config file missing",
			args:       []string{"--config=" + validConfig(t)},
			wantCode:   exitError,
			wantStderr: "cannot start listeners",
		},
		{
			name:       "missing config file",
			args:       []string{"--config=" + missing},
			wantCode:   exitError,
			wantStderr: "cannot load configuration",
		},
		{
			name:       "unknown config key",
			args:       []string{"--config=" + writeFile(t, "listners: []\n")},
			wantCode:   exitError,
			wantStderr: "field listners not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if tt.wantStdout == "" && stdout.Len() > 0 {
				t.Errorf("unexpected stdout: %q", stdout.String())
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestVersionLineIsSingleLine(t *testing.T) {
	line := versionLine()
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("version line spans several lines: %q", line)
	}
	for _, field := range []string{"version=", "revision=", "branch=", "go="} {
		if !strings.Contains(line, field) {
			t.Errorf("version line %q lacks %q", line, field)
		}
	}
}

func TestLogFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
		check  func(t *testing.T, line string)
	}{
		{
			name:   "logfmt by default",
			format: "",
			check: func(t *testing.T, line string) {
				for _, want := range []string{"time=", "level=", "msg="} {
					if !strings.Contains(line, want) {
						t.Errorf("logfmt line %q lacks %q", line, want)
					}
				}
			},
		},
		{
			name:   "json",
			format: "json",
			check: func(t *testing.T, line string) {
				var obj map[string]any
				if err := json.Unmarshal([]byte(line), &obj); err != nil {
					t.Fatalf("line is not JSON: %q: %v", line, err)
				}
				for _, key := range []string{"time", "level", "msg"} {
					if _, ok := obj[key]; !ok {
						t.Errorf("JSON line %q lacks key %q", line, key)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--config=" + validConfig(t)}
			if tt.format != "" {
				args = append(args, "--log.format="+tt.format)
			}
			var stdout, stderr bytes.Buffer
			run(context.Background(), args, &stdout, &stderr)

			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			if len(lines) == 0 || lines[0] == "" {
				t.Fatal("no log output")
			}
			for _, line := range lines {
				tt.check(t, line)
			}
		})
	}
}

func TestLogLevelFiltersInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run(context.Background(), []string{"--config=" + validConfig(t), "--log.level=error"}, &stdout, &stderr)

	out := stderr.String()
	if strings.Contains(out, "starting") {
		t.Errorf("info line logged at level error: %q", out)
	}
	if !strings.Contains(out, "cannot start listeners") {
		t.Errorf("error line missing: %q", out)
	}
}

// validConfig writes a minimal valid configuration file and returns its path.
func validConfig(t *testing.T) string {
	t.Helper()
	return writeFile(t, `
metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/exporter_proxy/web-metrics.yml
listeners:
  - name: node
    listen: ":9100"
    web_config_file: /etc/exporter_proxy/web.yml
    routes:
      - path: /metrics
        upstream: http://127.0.0.1:19100/metrics
`)
}

// writeFile writes content to a temporary config file and returns its path.
func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freePort returns a TCP port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// servingConfig writes a configuration serving a metrics file on port and
// the proxy metrics on metricsPort, with an empty web configuration (plain
// HTTP, no authentication).
func servingConfig(t *testing.T, port, metricsPort int) string {
	t.Helper()
	dir := t.TempDir()
	prom := filepath.Join(dir, "m.prom")
	web := filepath.Join(dir, "web.yml")
	if err := os.WriteFile(prom, []byte("up 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(web, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, fmt.Sprintf(`
metrics:
  listen: "127.0.0.1:%d"
  web_config_file: %s
listeners:
  - name: files
    listen: "127.0.0.1:%d"
    web_config_file: %s
    routes:
      - path: /metrics
        file: %s
        max_age: 1h
`, metricsPort, web, port, web, prom))
}

func TestRunServesUntilCanceled(t *testing.T) {
	port, metricsPort := freePort(t), freePort(t)
	cfg := servingConfig(t, port, metricsPort)

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"--config=" + cfg}, io.Discard, &stderr) }()

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if body != "up 1\n" {
		t.Fatalf("served body = %q, want %q", body, "up 1\n")
	}

	// The proxy's own metrics reflect the scrape above.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{
		`exporter_proxy_requests_total{code="200",listener="files",route="/metrics"} 1`,
		`exporter_proxy_source_errors_total{listener="files",reason="stale",route="/metrics"} 0`,
		`exporter_proxy_build_info{`,
		`exporter_proxy_config_hash `,
		`exporter_proxy_config_last_reload_successful 1`,
		`exporter_proxy_file_modified_timestamp_seconds{listener="files",route="/metrics"}`,
	} {
		if !strings.Contains(string(m), want) {
			t.Errorf("metrics lack %q", want)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Errorf("exit code = %d, want 0 (stderr: %s)", code, &stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop after cancellation")
	}
	if !strings.Contains(stderr.String(), "shutting down") {
		t.Errorf("shutdown not logged: %s", &stderr)
	}
}

func TestRunFailsWhenPortIsBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := servingConfig(t, ln.Addr().(*net.TCPAddr).Port, freePort(t))

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"--config=" + cfg}, io.Discard, &stderr)
	if code != exitError {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "address already in use") {
		t.Errorf("stderr = %s, want bind error", &stderr)
	}
}

func TestRunCheck(t *testing.T) {
	// A valid setup passes without binding any port: the busy port is
	// irrelevant to --check.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	good := servingConfig(t, busy.Addr().(*net.TCPAddr).Port, freePort(t))

	invalid := writeFile(t, `
metrics:
  listen: ":9999"
listeners:
  - name: a
    listen: ":9100"
    routes:
      - path: metrics
        file: relative.prom
`)
	missingFile := strings.Replace(readFile(t, good), "m.prom", "absent.prom", 1)

	tests := []struct {
		name       string
		config     string
		wantCode   int
		wantStderr []string
	}{
		{"valid setup", good, exitOK, []string{"check passed", "hash="}},
		{"invalid configuration", invalid, exitError, []string{
			`problem="metrics: web_config_file is required"`,
			`problem="listener \"a\": web_config_file is required"`,
			"path must start with '/'",
			"check failed",
		}},
		{"missing metrics file", writeFile(t, missingFile), exitError, []string{"absent.prom", "no such file", "problems=1"}},
		{"missing config file", filepath.Join(t.TempDir(), "nope.yml"), exitError, []string{"cannot load configuration"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"--check", "--config=" + tt.config}, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\n%s", code, tt.wantCode, &stderr)
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr.String(), w) {
					t.Errorf("stderr lacks %q:\n%s", w, &stderr)
				}
			}
			if strings.Contains(stderr.String(), "Listening on") {
				t.Error("--check started a listener")
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
