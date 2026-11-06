package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	if !strings.Contains(logs.String(), "msg=listening") {
		t.Errorf("listener start not logged: %s", &logs)
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

// fakeSystemd replaces systemd socket activation with the given sockets.
func fakeSystemd(t *testing.T, sockets map[string][]net.Listener) {
	t.Helper()
	orig := systemdListeners
	systemdListeners = func() (map[string][]net.Listener, error) { return sockets, nil }
	t.Cleanup(func() { systemdListeners = orig })
}

func tcpListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// isClosed reports whether ln no longer accepts connections.
func isClosed(ln net.Listener) bool {
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

func TestSystemdSocketActivation(t *testing.T) {
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(webConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)

	activated := tcpListener(t)
	unused := tcpListener(t)
	fakeSystemd(t, map[string][]net.Listener{
		"node":  {activated},
		"spare": {unused},
	})

	viaSystemd := listenerConfig("node", webConfig, up.URL)
	viaSystemd.Listen = "systemd:node"
	direct := listenerConfig("direct", webConfig, up.URL)

	var logs syncBuffer
	s := startServer(t, &config.Config{Listeners: []config.Listener{viaSystemd, direct}}, &logs)

	if got := s.Addr("node").String(); got != activated.Addr().String() {
		t.Errorf("node listener address = %s, want the systemd socket %s", got, activated.Addr())
	}
	for _, name := range []string{"node", "direct"} {
		if code, body := get(t, "http://"+s.Addr(name).String()+"/metrics", "", ""); code != http.StatusOK || body != metrics {
			t.Errorf("%s: code=%d body=%q", name, code, body)
		}
	}
	if !isClosed(unused) {
		t.Error("unused systemd socket left open")
	}
	if !strings.Contains(logs.String(), "systemd socket not used") {
		t.Errorf("unused socket not logged: %s", logs.String())
	}
}

func TestSystemdSocketErrors(t *testing.T) {
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(webConfig, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		sockets func(t *testing.T) map[string][]net.Listener
		wantErr string
	}{
		{
			name:    "socket missing",
			sockets: func(*testing.T) map[string][]net.Listener { return map[string][]net.Listener{} },
			wantErr: `no systemd socket named "node"`,
		},
		{
			name: "two sockets with the same name",
			sockets: func(t *testing.T) map[string][]net.Listener {
				return map[string][]net.Listener{"node": {tcpListener(t), tcpListener(t)}}
			},
			wantErr: "must be exactly one stream socket, got 2",
		},
		{
			name: "datagram socket only",
			sockets: func(*testing.T) map[string][]net.Listener {
				return map[string][]net.Listener{"node": {nil}}
			},
			wantErr: "must be exactly one stream socket, got 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sockets := tt.sockets(t)
			fakeSystemd(t, sockets)
			l := listenerConfig("node", webConfig, "http://127.0.0.1:1")
			l.Listen = "systemd:node"

			_, err := Start(&config.Config{Listeners: []config.Listener{l}}, Options{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Start error = %v, want %q", err, tt.wantErr)
			}
			for _, lns := range sockets {
				for _, ln := range lns {
					if ln != nil && !isClosed(ln) {
						t.Error("socket left open after failed start")
					}
				}
			}
		})
	}
}

func TestMetricsEndpoint(t *testing.T) {
	webConfig := filepath.Join(t.TempDir(), "web.yml")
	basicAuthWebConfig(t, webConfig, "vm", "metrics-pass")
	plain := filepath.Join(t.TempDir(), "plain.yml")
	if err := os.WriteFile(plain, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "exporter_proxy_up 1\n")
	})
	s, err := Start(&config.Config{
		Metrics:   config.MetricsEndpoint{Listen: "127.0.0.1:0", WebConfigFile: webConfig},
		Listeners: []config.Listener{listenerConfig("node", plain, "http://127.0.0.1:1")},
	}, Options{MetricsHandler: metricsHandler})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	url := "http://" + s.Addr(MetricsListener).String() + "/metrics"
	if code, _ := get(t, url, "", ""); code != http.StatusUnauthorized {
		t.Errorf("metrics without credentials: code %d, want 401 (own web config)", code)
	}
	if code, body := get(t, url, "vm", "metrics-pass"); code != http.StatusOK || body != "exporter_proxy_up 1\n" {
		t.Errorf("metrics with credentials: code %d body %q", code, body)
	}
}

// writeWeb writes a web configuration file with the given content.
func writeWeb(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func route(path, upstreamURL string) config.Route {
	return config.Route{Path: path, Upstream: upstreamURL + "/metrics", Limits: limits()}
}

// freeAddr returns a loopback address with a port that was free a moment
// ago. Reload compares listen values as written, so tests use real ports
// rather than ":0" (which validation rejects anyway).
func freeAddr(t *testing.T) string {
	t.Helper()
	ln := tcpListener(t)
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func withAddr(t *testing.T, l config.Listener) config.Listener {
	t.Helper()
	l.Listen = freeAddr(t)
	return l
}

func TestReloadSwapsRoutesKeepingTheSocket(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()

	l.Listen = addr // same address: the socket must be kept
	l.Routes = []config.Route{route("/new", up.URL)}
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := s.Addr("node").String(); got != addr {
		t.Errorf("address changed: %s -> %s", addr, got)
	}
	if code, _ := get(t, "http://"+addr+"/new", "", ""); code != http.StatusOK {
		t.Errorf("new route: code %d, want 200", code)
	}
	if code, _ := get(t, "http://"+addr+"/metrics", "", ""); code != http.StatusNotFound {
		t.Errorf("removed route: code %d, want 404", code)
	}
}

func TestReloadNewWebConfigOnSameAddress(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	plain := writeWeb(t, dir, "plain.yml", "{}\n")
	auth := filepath.Join(dir, "auth.yml")
	basicAuthWebConfig(t, auth, "prometheus", "s3cret-test")

	l := withAddr(t, listenerConfig("node", plain, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	url := "http://" + addr + "/metrics"
	if code, _ := get(t, url, "", ""); code != http.StatusOK {
		t.Fatalf("before reload: code %d", code)
	}

	l.Listen = addr
	l.WebConfigFile = auth
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// The old server stops gracefully; new connections reach the new one.
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, _ := get(t, url, "", "")
		if code == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still served without authentication after reload (code %d)", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code, _ := get(t, url, "prometheus", "s3cret-test"); code != http.StatusOK {
		t.Errorf("with credentials after reload: code %d, want 200", code)
	}
}

func TestReloadAddsAndRemovesListeners(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")

	old := withAddr(t, listenerConfig("old", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{old}}, io.Discard)
	oldAddr := s.Addr("old").String()

	added := withAddr(t, listenerConfig("added", web, up.URL))
	if err := s.Reload(&config.Config{Listeners: []config.Listener{added}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if s.Addr("old") != nil {
		t.Error("removed listener still known")
	}
	newAddr := s.Addr("added")
	if newAddr == nil {
		t.Fatal("added listener not started")
	}
	if code, _ := get(t, "http://"+newAddr.String()+"/metrics", "", ""); code != http.StatusOK {
		t.Errorf("added listener: code %d, want 200", code)
	}

	// The removed listener's port is eventually closed.
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", oldAddr, 200*time.Millisecond)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("removed listener still accepts connections")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestReloadRenamedListenerKeepsThePort(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")

	l := withAddr(t, listenerConfig("before", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("before").String()

	l.Name = "after"
	l.Listen = addr
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v (the address must be reused, not bound again)", err)
	}
	if got := s.Addr("after"); got == nil || got.String() != addr {
		t.Fatalf("renamed listener address = %v, want %s", got, addr)
	}
	if code, _ := get(t, "http://"+addr+"/metrics", "", ""); code != http.StatusOK {
		t.Errorf("after rename: code %d, want 200", code)
	}
}

func TestReloadFailureLeavesRunningConfiguration(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	busy := tcpListener(t)
	defer func() { _ = busy.Close() }()

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	l.Listen = addr

	tests := []struct {
		name    string
		cfg     func() *config.Config
		wantErr string
	}{
		{
			name: "port in use",
			cfg: func() *config.Config {
				other := withAddr(t, listenerConfig("other", web, up.URL))
				other.Listen = busy.Addr().String()
				changed := l
				changed.Routes = []config.Route{route("/changed", up.URL)}
				return &config.Config{Listeners: []config.Listener{changed, other}}
			},
			wantErr: `listener "other"`,
		},
		{
			name: "invalid web configuration",
			cfg: func() *config.Config {
				bad := l
				bad.WebConfigFile = writeWeb(t, dir, "bad.yml", "nope: 1\n")
				return &config.Config{Listeners: []config.Listener{bad}}
			},
			wantErr: "invalid web configuration",
		},
		{
			name: "new systemd socket",
			cfg: func() *config.Config {
				sd := withAddr(t, listenerConfig("sd", web, up.URL))
				sd.Listen = "systemd:sd"
				return &config.Config{Listeners: []config.Listener{l, sd}}
			},
			wantErr: "only taken at startup",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Reload(tt.cfg())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Reload error = %v, want %q", err, tt.wantErr)
			}
			// Untouched: same address, same routes.
			if got := s.Addr("node").String(); got != addr {
				t.Errorf("address changed to %s", got)
			}
			if code, _ := get(t, "http://"+addr+"/metrics", "", ""); code != http.StatusOK {
				t.Errorf("original route: code %d, want 200", code)
			}
			if code, _ := get(t, "http://"+addr+"/changed", "", ""); code != http.StatusNotFound {
				t.Errorf("route from the failed reload is served (code %d)", code)
			}
		})
	}
}

func TestReloadLetsInFlightRequestsFinish(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, metrics)
	}))
	defer slow.Close()
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")

	s := startServer(t, &config.Config{Listeners: []config.Listener{withAddr(t, listenerConfig("slow", web, slow.URL))}}, io.Discard)
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

	// Remove the listener while its request is running.
	var gotAuth atomic.Value
	other := listenerConfig("other", web, upstream(t, &gotAuth).URL)
	if err := s.Reload(&config.Config{Listeners: []config.Listener{other}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	close(release)

	if r := <-resc; r.code != http.StatusOK || r.body != metrics {
		t.Errorf("in-flight request during reload: code=%d body=%q, want 200", r.code, r.body)
	}
}

// testTLSFiles writes the certificate and key of an httptest TLS server
// into dir and returns their paths.
func testTLSFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	c := ts.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeWeb(t, dir, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})))
	writeWeb(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return certPath, keyPath
}

// TLS enabled in the same web configuration file: the reload restarts the
// listener with TLS instead of keeping it in clear text.
func TestReloadEnablesTLSInSameWebConfig(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	if code, _ := get(t, "http://"+addr+"/metrics", "", ""); code != http.StatusOK {
		t.Fatalf("before reload: code %d", code)
	}

	cert, key := testTLSFiles(t, dir)
	writeWeb(t, dir, "web.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", cert, key))
	l.Listen = addr
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
		DisableKeepAlives: true,
	}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := client.Get("https://" + addr + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("over TLS after reload: code %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not served over TLS after reload: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// rate_limit changed in the same web configuration file applies on reload.
func TestReloadAppliesRateLimitChange(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	url := "http://" + addr + "/metrics"

	writeWeb(t, dir, "web.yml", "rate_limit:\n  interval: 1h\n  burst: 1\n")
	l.Listen = addr
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// The previous server may answer a few more requests while it stops.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if code, _ := get(t, url, "", ""); code == http.StatusTooManyRequests {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rate_limit not applied after reload")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
