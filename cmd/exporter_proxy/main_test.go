package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			name:       "not implemented yet",
			args:       []string{"--config=" + validConfig(t)},
			wantCode:   exitError,
			wantStderr: "proxy not implemented yet",
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
			code := run(tt.args, &stdout, &stderr)

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
			run(args, &stdout, &stderr)

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
	run([]string{"--config=" + validConfig(t), "--log.level=error"}, &stdout, &stderr)

	out := stderr.String()
	if strings.Contains(out, "starting") {
		t.Errorf("info line logged at level error: %q", out)
	}
	if !strings.Contains(out, "proxy not implemented yet") {
		t.Errorf("error line missing: %q", out)
	}
}

// validConfig writes a minimal valid configuration file and returns its path.
func validConfig(t *testing.T) string {
	t.Helper()
	return writeFile(t, `
listeners:
  - name: node
    listen: ":9100"
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
