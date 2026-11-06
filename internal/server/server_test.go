package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

const metrics = "# TYPE up gauge\nup 1\n"

func limits() config.Limits {
	return config.Limits{Timeout: 2 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 100}
}

// basicAuthWebConfig writes a web configuration with one basic auth user.
// No TLS here: TLS and mTLS are covered by the end-to-end tests.
func basicAuthWebConfig(t *testing.T, path, user, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf("basic_auth_users:\n  %s: %s\n", user, hash)
	// Write then rename, like an administrator's deployment tool would.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// upstream records the Authorization header it receives.
func upstream(t *testing.T, gotAuth *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, metrics)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func listenerConfig(name, webConfig, upstreamURL string) config.Listener {
	return config.Listener{
		Name:                  name,
		Listen:                "127.0.0.1:0",
		WebConfigFile:         webConfig,
		MaxConcurrentRequests: 2,
		Routes: []config.Route{{
			Path:     "/metrics",
			Upstream: upstreamURL + "/metrics",
			Limits:   limits(),
		}},
	}
}

func startServer(t *testing.T, cfg *config.Config, logs io.Writer) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(logs, nil))
	s, err := Start(cfg, Options{Logger: logger})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func get(t *testing.T, url, user, password string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestBasicAuth(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	basicAuthWebConfig(t, webConfig, "prometheus", "s3cret-test")

	s := startServer(t, &config.Config{Listeners: []config.Listener{
		listenerConfig("auth", webConfig, up.URL),
	}}, io.Discard)
	url := "http://" + s.Addr("auth").String() + "/metrics"

	tests := []struct {
		name     string
		user     string
		password string
		want     int
	}{
		{"no credentials", "", "", http.StatusUnauthorized},
		{"wrong password", "prometheus", "wrong", http.StatusUnauthorized},
		{"unknown user", "nobody", "s3cret-test", http.StatusUnauthorized},
		{"valid credentials", "prometheus", "s3cret-test", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuth.Store("")
			code, body := get(t, url, tt.user, tt.password)
			if code != tt.want {
				t.Errorf("code = %d, want %d", code, tt.want)
			}
			if tt.want == http.StatusOK && body != metrics {
				t.Errorf("body = %q", body)
			}
			if a, _ := gotAuth.Load().(string); a != "" {
				t.Errorf("Authorization forwarded upstream: %q", a)
			}
		})
	}
}

func TestWebConfigReloadedWithoutRestart(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	basicAuthWebConfig(t, webConfig, "prometheus", "old-password")

	s := startServer(t, &config.Config{Listeners: []config.Listener{
		listenerConfig("auth", webConfig, up.URL),
	}}, io.Discard)
	url := "http://" + s.Addr("auth").String() + "/metrics"

	if code, _ := get(t, url, "prometheus", "old-password"); code != http.StatusOK {
		t.Fatalf("before change: code = %d, want 200", code)
	}

	basicAuthWebConfig(t, webConfig, "prometheus", "new-password")

	if code, _ := get(t, url, "prometheus", "old-password"); code != http.StatusUnauthorized {
		t.Errorf("old password after change: code = %d, want 401", code)
	}
	if code, _ := get(t, url, "prometheus", "new-password"); code != http.StatusOK {
		t.Errorf("new password after change: code = %d, want 200", code)
	}
}

func TestStartRejectsInvalidWebConfigs(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(bad, []byte("basic_auth_users:\n  prometheus: [not, a, hash]\nunknown_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yml")

	_, err := Start(&config.Config{Listeners: []config.Listener{
		listenerConfig("bad", bad, "http://127.0.0.1:1"),
		listenerConfig("missing", missing, "http://127.0.0.1:1"),
	}}, Options{})
	if err == nil {
		t.Fatal("Start succeeded with invalid web configurations")
	}
	for _, want := range []string{`listener "bad"`, `listener "missing"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not report %s", err, want)
		}
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("error spans several lines: %q", err)
	}
}

func TestStartReleasesPortsWhenOneBindFails(t *testing.T) {
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(webConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()

	// Reserve a free port for the first listener.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddr := probe.Addr().String()
	_ = probe.Close()

	first := listenerConfig("first", webConfig, "http://127.0.0.1:1")
	first.Listen = firstAddr
	second := listenerConfig("second", webConfig, "http://127.0.0.1:1")
	second.Listen = busy.Addr().String()

	_, err = Start(&config.Config{Listeners: []config.Listener{first, second}}, Options{})
	if err == nil || !strings.Contains(err.Error(), `listener "second"`) {
		t.Fatalf("Start error = %v, want bind failure on second", err)
	}

	// The first address must have been released.
	ln, err := net.Listen("tcp", firstAddr)
	if err != nil {
		t.Fatalf("first listener address still bound after failed start: %v", err)
	}
	_ = ln.Close()
}

func TestShutdownWaitsForInFlightRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, metrics)
	}))
	defer up.Close()

	webConfig := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(webConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s, err := Start(&config.Config{Listeners: []config.Listener{
		listenerConfig("slow", webConfig, up.URL),
	}}, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + s.Addr("slow").String() + "/metrics"

	type result struct {
		code int
		body string
	}
	resc := make(chan result, 1)
	go func() {
		code, body := get(t, url, "", "")
		resc <- result{code, body}
	}()
	<-started

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- s.Shutdown(ctx)
	}()

	// Shutdown must wait for the in-flight request.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before the request completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	if err := <-shutdownDone; err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if r := <-resc; r.code != http.StatusOK || r.body != metrics {
		t.Errorf("in-flight request: code=%d body=%q, want 200 with metrics", r.code, r.body)
	}

	// New connections are refused after shutdown.
	if _, err := http.Get(url); err == nil {
		t.Error("server still accepts connections after Shutdown")
	}
	if !strings.Contains(logs.String(), "Listening on") {
		t.Errorf("listener start not logged: %s", &logs)
	}
}

func TestBasicAuthWithoutTLS(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"empty", "{}\n", false},
		{"users without TLS", "basic_auth_users:\n  u: hash\n", true},
		{"users with TLS files", "tls_server_config:\n  cert_file: /c\n  key_file: /k\nbasic_auth_users:\n  u: hash\n", false},
		{"users with inline cert", "tls_server_config:\n  cert: x\nbasic_auth_users:\n  u: hash\n", false},
		{"TLS without users", "tls_server_config:\n  cert_file: /c\n  key_file: /k\n", false},
		{"mTLS only", "tls_server_config:\n  client_ca_file: /ca\n  client_auth_type: RequireAndVerifyClientCert\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "web.yml")
			if err := os.WriteFile(p, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := basicAuthWithoutTLS(p)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("basicAuthWithoutTLS = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStartWarnsOnClearTextBasicAuth(t *testing.T) {
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	basicAuthWebConfig(t, webConfig, "prometheus", "s3cret-test")

	var logs syncBuffer
	startServer(t, &config.Config{Listeners: []config.Listener{
		listenerConfig("clear", webConfig, "http://127.0.0.1:1"),
	}}, &logs)

	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "credentials travel in clear text") {
		t.Errorf("no clear-text warning in logs: %s", logs.String())
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writes (server
// goroutines) and reads (the test).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
