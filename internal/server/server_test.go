package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
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
	// Atomically, like the README asks: a request reading a file being
	// rewritten in place would see it empty, which is refused (518).
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
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

// An unreadable web configuration refuses new TLS connections and is
// reported as a failed read.
func TestTLSWebConfigUnreadableIsRecorded(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	web := writeWeb(t, dir, "web.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", cert, key))

	rec := &authRecorder{}
	s, err := Start(&config.Config{Listeners: []config.Listener{listenerConfig("node", web, up.URL)}},
		Options{Logger: slog.New(slog.DiscardHandler), Recorder: rec})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	writeWeb(t, dir, "web.yml", "not: [valid\n")
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test certificate
	}}
	if resp, err := client.Get("https://" + s.Addr("node").String() + "/metrics"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("TLS connection accepted with an unreadable web configuration")
	}
	if got := rec.reads(); !slices.Equal(got, []bool{false}) {
		t.Errorf("web configuration reads recorded %v, want [false]", got)
	}
}

// Users removed from the file of a listener started with basic auth: 518,
// and a reload is refused, since it would remove authentication; a
// restart applies it.
func TestUsersRemovedFailClosedUntilReload(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := filepath.Join(dir, "web.yml")
	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	url := "http://" + addr + "/metrics"

	writeWeb(t, dir, "web.yml", "{}\n") // users removed while running
	if code, body := get(t, url, "", ""); code != StatusWebConfigUnreadable {
		t.Fatalf("without users: code %d body %q, want 518", code, body)
	}

	l.Listen = addr
	expectWeakeningRefused(t, s.Reload(&config.Config{Listeners: []config.Listener{l}}), "basic authentication")
	if code, _ := get(t, url, "", ""); code != StatusWebConfigUnreadable {
		t.Errorf("after the refused reload: code %d, want 518", code)
	}

	// A restart (a new server) applies the file without authentication.
	l2 := withAddr(t, listenerConfig("node", web, up.URL))
	s2 := startServer(t, &config.Config{Listeners: []config.Listener{l2}}, io.Discard)
	if code, _ := get(t, "http://"+s2.Addr("node").String()+"/metrics", "", ""); code != http.StatusOK {
		t.Errorf("after a restart: code %d, want 200", code)
	}
}

// expectWeakeningRefused checks that err refuses a reload weakening what.
func expectWeakeningRefused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "would weaken authentication") || !strings.Contains(err.Error(), what) {
		t.Errorf("Reload error = %v, want a refusal weakening %s", err, what)
	}
}

// Verified credentials survive a restart of the listener on reload.
func TestSuccessCacheKeptAcrossListenerRestart(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := filepath.Join(dir, "web.yml")
	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	if code, _ := get(t, "http://"+addr+"/metrics", "prometheus", "s3cret-test"); code != http.StatusOK {
		t.Fatalf("first scrape: code %d", code)
	}
	before := s.successes["node"]

	// rate_limit added in the same file: the listener restarts.
	content, err := os.ReadFile(web)
	if err != nil {
		t.Fatal(err)
	}
	writeWeb(t, dir, "web.yml", string(content)+"rate_limit:\n  interval: 1ms\n  burst: 100\n")
	l.Listen = addr
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.mu.Lock()
	after := s.successes["node"]
	restarted := s.listeners["node"].settings.rateLimit.burst == 100
	s.mu.Unlock()
	if !restarted {
		t.Fatal("listener not restarted")
	}
	if after != before || len(after.keys) != 1 {
		t.Errorf("success cache not kept across the restart (same=%v, entries=%d)", after == before, len(after.keys))
	}
}

// Users added then removed while running: 518, kept by a refused reload.
func TestUsersSeenAtRuntimeClearedByReload(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")

	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	url := "http://" + addr + "/metrics"

	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")
	if code, _ := get(t, url, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("users added: code %d, want 401", code)
	}
	writeWeb(t, dir, "web.yml", "{}\n")
	if code, _ := get(t, url, "", ""); code != StatusWebConfigUnreadable {
		t.Fatalf("users removed: code %d, want 518", code)
	}

	l.Listen = addr
	expectWeakeningRefused(t, s.Reload(&config.Config{Listeners: []config.Listener{l}}), "basic authentication")
	if code, _ := get(t, url, "", ""); code != StatusWebConfigUnreadable {
		t.Errorf("after the refused reload: code %d, want 518", code)
	}

	// Users back: the reload is accepted again (nothing weakened).
	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Errorf("reload with the users back: %v", err)
	}
}

// A renamed listener on the same address that loses its users: the reload
// is refused, and the port keeps its authentication.
func TestRenamedListenerLosingAuthIsWarned(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.yml")
	basicAuthWebConfig(t, auth, "prometheus", "s3cret-test")
	plain := writeWeb(t, dir, "plain.yml", "{}\n")

	l := withAddr(t, listenerConfig("node", auth, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	renamed := listenerConfig("node2", plain, up.URL)
	renamed.Listen = addr
	expectWeakeningRefused(t, s.Reload(&config.Config{Listeners: []config.Listener{renamed}}), "basic authentication")
	if code, _ := get(t, "http://"+addr+"/metrics", "", ""); code != http.StatusUnauthorized {
		t.Errorf("port lost its authentication: code %d, want 401", code)
	}
}

// mtlsTest is a TLS listener whose server certificate also serves as a
// client certificate.
type mtlsTest struct {
	s         *Server
	l         config.Listener
	web       string
	cert, key string
	logs      *syncBuffer
	rec       *authRecorder
}

func newMTLSTest(t *testing.T, clientAuth string) *mtlsTest {
	t.Helper()
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	m := &mtlsTest{web: filepath.Join(dir, "web.yml"), logs: &syncBuffer{}, rec: &authRecorder{}}
	m.cert, m.key = testTLSFiles(t, dir)
	m.writeWeb(t, clientAuth)
	m.l = withAddr(t, listenerConfig("node", m.web, up.URL))
	s, err := Start(&config.Config{Listeners: []config.Listener{m.l}},
		Options{Logger: slog.New(slog.NewTextHandler(m.logs, nil)), Recorder: m.rec})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	m.s = s
	m.l.Listen = s.Addr("node").String()
	return m
}

func (m *mtlsTest) writeWeb(t *testing.T, clientAuth string) {
	t.Helper()
	content := fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", m.cert, m.key)
	if clientAuth != "" {
		content += "  client_auth_type: " + clientAuth + "\n"
	}
	writeWeb(t, filepath.Dir(m.web), filepath.Base(m.web), content)
}

func (m *mtlsTest) url() string { return "https://" + m.l.Listen + "/metrics" }

func (m *mtlsTest) reload(t *testing.T) {
	t.Helper()
	if err := m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

// tlsClient returns a client, with the test certificate when withCert.
func (m *mtlsTest) client(t *testing.T, withCert, keepAlive bool) *http.Client {
	t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test certificate
	if withCert {
		pair, err := tls.LoadX509KeyPair(m.cert, m.key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: !keepAlive}}
}

func tlsGet(c *http.Client, url string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("code %d", resp.StatusCode)
	}
	return nil
}

// A web configuration that stops requiring client certificates while
// running refuses new connections, and the reload that would apply it is
// refused too.
func TestClientAuthFailsClosedUntilReload(t *testing.T) {
	m := newMTLSTest(t, "RequireAnyClientCert")
	anonymous := m.client(t, false, false)
	if err := tlsGet(anonymous, m.url()); err == nil {
		t.Fatal("served without a client certificate at start")
	}
	if err := tlsGet(m.client(t, true, false), m.url()); err != nil {
		t.Fatalf("with a client certificate at start: %v", err)
	}

	clientFailures := len(m.rec.got()) // the anonymous attempt above
	m.writeWeb(t, "")                  // client_auth_type lost: half-written or weakened
	if err := tlsGet(anonymous, m.url()); err == nil {
		t.Fatal("served without a client certificate after the file lost client_auth_type")
	}
	if got := m.rec.reads(); !slices.Contains(got, false) {
		t.Errorf("weakened file not reported as a failed read: %v", got)
	}
	if got := m.rec.got(); len(got) != clientFailures {
		t.Errorf("server-side refusal counted as a client failure: %v", got)
	}

	expectWeakeningRefused(t, m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}), "client certificate requirements")
	if err := tlsGet(anonymous, m.url()); err == nil {
		t.Error("served without a client certificate after the refused reload")
	}
}

// A reload that requires client certificates closes the connections
// already open, which were accepted without one.
func TestClientAuthTightenedByReloadClosesOpenConnections(t *testing.T) {
	m := newMTLSTest(t, "")
	c := m.client(t, false, true) // keep-alive, no certificate
	if err := tlsGet(c, m.url()); err != nil {
		t.Fatalf("before: %v", err)
	}

	m.writeWeb(t, "RequireAnyClientCert")
	m.reload(t)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(c, m.url()) == nil {
		if time.Now().After(deadline) {
			t.Fatal("open connection still served without a certificate after the reload")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tlsGet(m.client(t, true, false), m.url()); err != nil {
		t.Errorf("with a certificate after the reload: %v", err)
	}
}

// Unchanged client certificate settings keep the listener and its
// connections on reload.
func TestReloadKeepsListenerWithSameClientAuth(t *testing.T) {
	m := newMTLSTest(t, "RequireAnyClientCert")
	m.s.mu.Lock()
	before := m.s.listeners["node"]
	m.s.mu.Unlock()
	m.reload(t)
	m.s.mu.Lock()
	after := m.s.listeners["node"]
	m.s.mu.Unlock()
	if before != after {
		t.Error("listener restarted although its settings did not change")
	}
}

// testClientPKI writes a client CA and a client certificate for san, signed
// by it, and returns their paths.
func testClientPKI(t *testing.T, dir, san string) (caPath, certPath, keyPath string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: san}, DNSNames: []string{san},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	caPath, certPath, keyPath = filepath.Join(dir, "client-ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	writeWeb(t, dir, "client-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	writeWeb(t, dir, "client.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeWeb(t, dir, "client-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	return caPath, certPath, keyPath
}

// writeMTLSWeb writes a web configuration verifying client certificates
// against ca (if set), restricted to sans (if any).
func (m *mtlsTest) writeMTLSWeb(t *testing.T, ca string, sans ...string) {
	t.Helper()
	content := fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_auth_type: RequireAndVerifyClientCert\n", m.cert, m.key)
	if ca != "" {
		content += "  client_ca_file: " + ca + "\n"
	}
	if len(sans) > 0 {
		content += "  client_allowed_sans:\n"
		for _, s := range sans {
			content += "    - " + s + "\n"
		}
	}
	writeWeb(t, filepath.Dir(m.web), filepath.Base(m.web), content)
}

// clientWith returns a client presenting the given certificate, without
// keep-alive, resuming TLS sessions when the server allows it.
func clientWith(t *testing.T, cert, key string) *http.Client {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ //nolint:gosec // test server certificate
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{pair},
			ClientSessionCache: tls.NewLRUClientSessionCache(8),
		},
		DisableKeepAlives: true,
	}}
}

// A client removed from client_allowed_sans while running cannot keep
// connecting by resuming its TLS session.
func TestAllowedSANsCheckedOnResumption(t *testing.T) {
	m := newMTLSTest(t, "")
	ca, cert, key := testClientPKI(t, filepath.Dir(m.web), "scraper-a")
	m.writeMTLSWeb(t, ca, "scraper-a")
	m.reload(t) // apply mTLS (restarts the listener)
	c := clientWith(t, cert, key)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(c, m.url()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("allowed client refused")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tlsGet(c, m.url()); err != nil { // a second connection, to get a ticket
		t.Fatalf("allowed client: %v", err)
	}

	m.writeMTLSWeb(t, ca, "scraper-b") // scraper-a revoked, no reload
	if err := tlsGet(c, m.url()); err == nil {
		t.Error("revoked client served by resuming its TLS session")
	}
}

// A client CA removed while running (verification would fall back to the
// system roots) refuses new connections until a reload, which warns.
func TestClientCARemovedFailsClosed(t *testing.T) {
	m := newMTLSTest(t, "")
	ca, cert, key := testClientPKI(t, filepath.Dir(m.web), "scraper-a")
	m.writeMTLSWeb(t, ca)
	m.reload(t)
	c := clientWith(t, cert, key)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(c, m.url()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("client refused with its CA configured")
		}
		time.Sleep(20 * time.Millisecond)
	}

	m.writeMTLSWeb(t, "") // client_ca_file lost, RequireAndVerifyClientCert kept
	fresh := clientWith(t, cert, key)
	if err := tlsGet(fresh, m.url()); err == nil {
		t.Error("served after the client CA was removed")
	}
	if got := m.rec.reads(); !slices.Contains(got, false) {
		t.Errorf("removed client CA not reported as a failed read: %v", got)
	}

	// Verification without a client CA is invalid: the reload is refused
	// and the running listener keeps its CA.
	if err := m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}); err == nil ||
		!strings.Contains(err.Error(), "no client_ca_file or client_ca") {
		t.Errorf("Reload error = %v, want the missing client CA", err)
	}
	m.writeMTLSWeb(t, ca)
	if err := tlsGet(clientWith(t, cert, key), m.url()); err != nil {
		t.Errorf("client refused once the CA is back: %v", err)
	}
}

// A reload catching a TLS file emptied would serve in clear text: refused.
func TestReloadLosingTLSIsWarned(t *testing.T) {
	m := newMTLSTest(t, "")
	writeWeb(t, filepath.Dir(m.web), filepath.Base(m.web), "{}\n")
	expectWeakeningRefused(t, m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}), "TLS")
}

// Listeners swapping addresses: the reload that removes the protection of
// a port is refused, whatever the listener names.
func TestSwappedListenersLosingAuthAreWarned(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.yml")
	basicAuthWebConfig(t, auth, "prometheus", "s3cret-test")
	plain := writeWeb(t, dir, "plain.yml", "{}\n")

	a := withAddr(t, listenerConfig("a", auth, up.URL))
	b := withAddr(t, listenerConfig("b", plain, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{a, b}}, io.Discard)
	a.Listen, b.Listen = s.Addr("b").String(), s.Addr("a").String() // swap
	err := s.Reload(&config.Config{Listeners: []config.Listener{a, b}})
	expectWeakeningRefused(t, err, "basic authentication")
	if err != nil && !strings.Contains(err.Error(), `listener "b"`) {
		t.Errorf("refusal does not name the listener taking the protected port: %v", err)
	}
}

// writeWebRaw writes the TLS part of m's web configuration plus extra.
func (m *mtlsTest) writeWebRaw(t *testing.T, extra string) {
	t.Helper()
	content := fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", m.cert, m.key) + extra
	writeWeb(t, filepath.Dir(m.web), filepath.Base(m.web), content)
}

// RequireAnyClientCert (required, not verified) and VerifyClientCertIfGiven
// (verified, not required) are not ranked: going from one to the other
// weakens what is required, refused while running and by a reload.
func TestClientCertRequiredNotTradedForVerified(t *testing.T) {
	m := newMTLSTest(t, "RequireAnyClientCert")
	ca, _, _ := testClientPKI(t, filepath.Dir(m.web), "scraper-a")
	anonymous := m.client(t, false, false)

	m.writeWebRaw(t, "  client_auth_type: VerifyClientCertIfGiven\n  client_ca_file: "+ca+"\n")
	if err := tlsGet(anonymous, m.url()); err == nil {
		t.Fatal("client without a certificate served after RequireAny became VerifyIfGiven")
	}
	expectWeakeningRefused(t, m.s.Reload(&config.Config{Listeners: []config.Listener{m.l}}), "client certificate requirements")
}

// The reverse: a verified certificate is not traded for any certificate.
func TestClientCertVerifiedNotTradedForRequired(t *testing.T) {
	m := newMTLSTest(t, "")
	ca, cert, key := testClientPKI(t, filepath.Dir(m.web), "scraper-a")
	m.writeWebRaw(t, "  client_auth_type: VerifyClientCertIfGiven\n  client_ca_file: "+ca+"\n")
	m.reload(t)
	if err := tlsGet(clientWith(t, cert, key), m.url()); err != nil {
		// The restarted listener may take a moment to replace the old one.
		time.Sleep(100 * time.Millisecond)
		if err := tlsGet(clientWith(t, cert, key), m.url()); err != nil {
			t.Fatalf("verified client refused: %v", err)
		}
	}

	m.writeWebRaw(t, "  client_auth_type: RequireAnyClientCert\n  client_ca_file: "+ca+"\n")
	// A self-signed certificate, from no trusted CA.
	if err := tlsGet(m.client(t, true, false), m.url()); err == nil {
		t.Error("unverified certificate accepted after VerifyIfGiven became RequireAny")
	}
}

// client_allowed_sans with an optional certificate: a client without one
// is refused as a client failure, without a panic in exporter-toolkit.
func TestAllowedSANsWithoutClientCert(t *testing.T) {
	m := newMTLSTest(t, "")
	ca, _, _ := testClientPKI(t, filepath.Dir(m.web), "scraper-a")
	m.writeWebRaw(t, "  client_auth_type: VerifyClientCertIfGiven\n  client_ca_file: "+ca+"\n  client_allowed_sans:\n    - scraper-a\n")
	m.reload(t)
	time.Sleep(100 * time.Millisecond) // old server stopping
	before := len(m.rec.got())
	if err := tlsGet(m.client(t, false, false), m.url()); err == nil {
		t.Fatal("client without a certificate served despite client_allowed_sans")
	}
	if strings.Contains(m.logs.String(), "panic") {
		t.Errorf("panic serving a client without a certificate: %s", m.logs.String())
	}
	if got := m.rec.got(); len(got) != before+1 || got[len(got)-1] != proxy.AuthTLSHandshake {
		t.Errorf("refusal not counted as a client tls_handshake failure: %v", got)
	}
}

// Client certificates required while running: refused until the reload
// (even for clients with a certificate), which then restarts the listener
// and closes the connections opened without a certificate.
func TestClientAuthTightenedWhileRunningAppliesAtReload(t *testing.T) {
	m := newMTLSTest(t, "")
	open := m.client(t, false, true) // keep-alive, no certificate
	if err := tlsGet(open, m.url()); err != nil {
		t.Fatalf("before: %v", err)
	}

	m.writeWeb(t, "RequireAnyClientCert")
	before := len(m.rec.got())
	if err := tlsGet(m.client(t, true, false), m.url()); err == nil {
		t.Fatal("new connection accepted while the file differs from the running settings")
	}
	if got := m.rec.got(); len(got) != before {
		t.Errorf("server-side refusal counted as a client failure: %v", got)
	}
	if got := m.rec.reads(); !slices.Contains(got, false) {
		t.Errorf("changed settings not reported as a failed read: %v", got)
	}

	m.reload(t)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(open, m.url()) == nil {
		if time.Now().After(deadline) {
			t.Fatal("connection opened without a certificate still served after the reload")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tlsGet(m.client(t, true, false), m.url()); err != nil {
		t.Errorf("with a certificate after the reload: %v", err)
	}
}

// The client CA content can be rotated without reload.
func TestClientCARotationWithoutReload(t *testing.T) {
	m := newMTLSTest(t, "")
	dir := filepath.Dir(m.web)
	ca1, cert1, key1 := testClientPKI(t, filepath.Join(dir), "scraper-a")
	m.writeWebRaw(t, "  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: "+ca1+"\n")
	m.reload(t)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(clientWith(t, cert1, key1), m.url()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("client of the first CA refused")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A second PKI; its CA replaces the content of the same file.
	other := t.TempDir()
	ca2, cert2, key2 := testClientPKI(t, other, "scraper-a")
	data, err := os.ReadFile(ca2)
	if err != nil {
		t.Fatal(err)
	}
	writeWeb(t, dir, filepath.Base(ca1), string(data))
	if err := tlsGet(clientWith(t, cert2, key2), m.url()); err != nil {
		t.Errorf("client of the rotated CA refused without reload: %v", err)
	}
	if err := tlsGet(clientWith(t, cert1, key1), m.url()); err == nil {
		t.Error("client of the replaced CA still accepted on a new connection")
	}
}

// "OPTIONS *" goes through authentication, not an automatic empty 200.
func TestOptionsStarRequiresAuthentication(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := filepath.Join(t.TempDir(), "web.yml")
	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")
	s := startServer(t, &config.Config{Listeners: []config.Listener{listenerConfig("node", web, up.URL)}}, io.Discard)

	conn, err := net.Dial("tcp", s.Addr("node").String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprint(conn, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("OPTIONS *: code %d, want 401", resp.StatusCode)
	}
}

// After new TLS connections failed on the server certificate, a request on
// a connection already open reports when the settings load again, instead
// of keeping web_config_read_error at 1 until the next handshake.
func TestTLSFailureClearedByRequestOnOpenConnection(t *testing.T) {
	m := newMTLSTest(t, "")
	open := m.client(t, false, true) // keep-alive
	if err := tlsGet(open, m.url()); err != nil {
		t.Fatalf("before: %v", err)
	}
	certPEM, err := os.ReadFile(m.cert)
	if err != nil {
		t.Fatal(err)
	}

	writeWeb(t, filepath.Dir(m.cert), filepath.Base(m.cert), "") // renewal in progress
	if err := tlsGet(m.client(t, false, false), m.url()); err == nil {
		t.Fatal("new connection accepted without a server certificate")
	}
	if ok, any := m.rec.lastTLSRead(); !any || ok {
		t.Fatalf("TLS failure not reported (ok=%v, any=%v)", ok, any)
	}

	writeWeb(t, filepath.Dir(m.cert), filepath.Base(m.cert), string(certPEM)) // renewed
	if err := tlsGet(open, m.url()); err != nil {
		t.Fatalf("request on the open connection: %v", err)
	}
	if ok, _ := m.rec.lastTLSRead(); !ok {
		t.Error("TLS settings loading again not reported by a request on an open connection")
	}
}

// Web configurations breaking exporter_proxy's own rules (accepted by
// exporter-toolkit) are all reported at once.
func TestStartReportsEveryWebConfigRuleViolation(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	// Verifying client certificates without a client CA.
	a := writeWeb(t, dir, "a.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_auth_type: RequireAndVerifyClientCert\n", cert, key))
	// A header exporter-toolkit forbids.
	b := writeWeb(t, dir, "b.yml", "http_server_config:\n  headers:\n    Set-Cookie: x\n")
	_, err := Start(&config.Config{Listeners: []config.Listener{
		withAddr(t, listenerConfig("a", a, up.URL)),
		withAddr(t, listenerConfig("b", b, up.URL)),
	}}, Options{Logger: slog.New(slog.DiscardHandler)})
	if err == nil || !strings.Contains(err.Error(), `listener "a"`) || !strings.Contains(err.Error(), `listener "b"`) {
		t.Errorf("Start error = %v, want both listeners reported", err)
	}
}

// otherNetworkListener is a listener reporting another network, like a
// datagram or seqpacket socket passed by systemd.
type otherNetworkListener struct {
	net.Listener
	network string
}

func (l otherNetworkListener) Addr() net.Addr { return otherNetworkAddr(l.network) }

type otherNetworkAddr string

func (a otherNetworkAddr) Network() string { return string(a) }
func (a otherNetworkAddr) String() string  { return "/run/x.sock" }

// systemd sockets that are not TCP or Unix stream sockets are refused at
// startup, instead of failing on Accept or showing client-chosen paths.
func TestSystemdNonStreamSocketsRefused(t *testing.T) {
	for _, network := range []string{"unixgram", "unixpacket"} {
		t.Run(network, func(t *testing.T) {
			ln := otherNetworkListener{tcpListener(t), network}
			fakeSystemd(t, map[string][]net.Listener{"node": {ln}})
			web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
			l := listenerConfig("node", web, "http://127.0.0.1:1")
			l.Listen = "systemd:node"
			_, err := Start(&config.Config{Listeners: []config.Listener{l}}, Options{Logger: slog.New(slog.DiscardHandler)})
			if err == nil || !strings.Contains(err.Error(), "stream socket") {
				t.Errorf("Start error = %v, want a refused non-stream socket", err)
			}
			if !isClosed(ln.Listener) {
				t.Error("refused socket left open")
			}
		})
	}
}

func TestQuotedSANsUnambiguous(t *testing.T) {
	if quotedSANs([]string{"a\nb"}) == quotedSANs([]string{"a", "b"}) {
		t.Error(`["a\nb"] and ["a","b"] share an encoding`)
	}
	if quotedSANs([]string{"b", "a"}) != quotedSANs([]string{"a", "b"}) {
		t.Error("order changes the encoding")
	}
	if quotedSANs(nil) != "" {
		t.Error("unset list not empty")
	}
}

// Sockets passed by systemd are closed and reported even when no listener
// uses systemd.
func TestUnusedSystemdSocketsClosedWithoutSystemdListeners(t *testing.T) {
	ln := tcpListener(t)
	fakeSystemd(t, map[string][]net.Listener{"leftover": {ln}})
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	logs := &syncBuffer{}
	startServer(t, &config.Config{Listeners: []config.Listener{withAddr(t, listenerConfig("node", web, "http://127.0.0.1:1"))}}, logs)
	if !isClosed(ln) {
		t.Error("unused systemd socket left open")
	}
	if !strings.Contains(logs.String(), "systemd socket not used by any listener") {
		t.Errorf("unused systemd socket not reported: %s", logs.String())
	}
}

// The Unix client connection wrapper keeps the graceful half-close.
func TestUnixClientConnCloseWrite(t *testing.T) {
	var c net.Conn = unixClientConn{&halfCloser{}}
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("CloseWrite hidden by the wrapper")
	}
	_ = cw.CloseWrite()
	if !c.(unixClientConn).Conn.(*halfCloser).closed {
		t.Error("CloseWrite not forwarded")
	}
}

type halfCloser struct {
	net.Conn
	closed bool
}

func (h *halfCloser) CloseWrite() error { h.closed = true; return nil }

// writeExpiredServerCert overwrites cert and key with a self-signed
// certificate that expired an hour ago.
func writeExpiredServerCert(t *testing.T, cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "expired"},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	writeWeb(t, filepath.Dir(cert), filepath.Base(cert), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeWeb(t, filepath.Dir(key), filepath.Base(key), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
}

// An expired server certificate is refused as a server-side failure: not
// counted as client tls_handshake failures, shown by web_config_read_error.
func TestExpiredServerCertificateIsServerSide(t *testing.T) {
	m := newMTLSTest(t, "")
	if err := tlsGet(m.client(t, false, false), m.url()); err != nil {
		t.Fatalf("before: %v", err)
	}
	writeExpiredServerCert(t, m.cert, m.key)
	before := len(m.rec.got())
	if err := tlsGet(m.client(t, false, false), m.url()); err == nil {
		t.Fatal("served with an expired server certificate")
	}
	if got := m.rec.got(); len(got) != before {
		t.Errorf("expired server certificate counted as client failures: %v", got)
	}
	if ok, any := m.rec.lastTLSRead(); !any || ok {
		t.Errorf("expired server certificate not reported (ok=%v, any=%v)", ok, any)
	}
}

// Users added to the file, even before any request saw them, do not make
// a reload restart the listener (requests enforce them anyway).
func TestReloadAfterUsersAddedKeepsListener(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()
	s.mu.Lock()
	before := s.listeners["node"]
	s.mu.Unlock()

	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.mu.Lock()
	after := s.listeners["node"]
	s.mu.Unlock()
	if after != before {
		t.Error("listener restarted by a reload that only found new users")
	}
	if code, _ := get(t, "http://"+l.Listen+"/metrics", "", ""); code != http.StatusUnauthorized {
		t.Errorf("users not enforced: code %d, want 401", code)
	}
}

// With an expired server certificate, no handshake reports the TLS settings
// as healthy: neither one stopping early (an old TLS version) nor a TLS 1.3
// session resumption, which is refused too.
func TestExpiredServerCertificateEveryHandshake(t *testing.T) {
	m := newMTLSTest(t, "")
	resuming := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ //nolint:gosec // test certificate
			InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(4),
		},
		DisableKeepAlives: true,
	}}
	for range 2 { // get a session ticket
		if err := tlsGet(resuming, m.url()); err != nil {
			t.Fatalf("before: %v", err)
		}
	}

	writeExpiredServerCert(t, m.cert, m.key)
	if err := tlsGet(resuming, m.url()); err == nil {
		t.Error("TLS 1.3 session resumed with an expired server certificate")
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ //nolint:gosec // test
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
	}}}
	_ = tlsGet(old, m.url())
	if ok, any := m.rec.lastTLSRead(); !any || ok {
		t.Errorf("TLS settings reported healthy with an expired certificate (ok=%v)", ok)
	}
}

// An expired server certificate on one listener is logged at startup, and
// only that listener's TLS connections are refused (as a server-side
// failure): the service and its other listeners start.
func TestStartWithExpiredServerCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	writeExpiredServerCert(t, cert, key)
	web := writeWeb(t, dir, "web.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", cert, key))
	plain := writeWeb(t, dir, "plain.yml", "{}\n")
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	logs := &syncBuffer{}
	rec := &authRecorder{}
	s, err := Start(&config.Config{Listeners: []config.Listener{
		withAddr(t, listenerConfig("tls", web, up.URL)),
		withAddr(t, listenerConfig("plain", plain, up.URL)),
	}}, Options{Logger: slog.New(slog.NewTextHandler(logs, nil)), Recorder: rec})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !strings.Contains(logs.String(), "server certificate outside its validity dates") {
		t.Errorf("expired certificate not logged at startup: %s", logs.String())
	}
	if code, _ := get(t, "http://"+s.Addr("plain").String()+"/metrics", "", ""); code != http.StatusOK {
		t.Errorf("other listener: code %d, want 200", code)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test
	if _, err := client.Get("https://" + s.Addr("tls").String() + "/metrics"); err == nil {
		t.Error("TLS listener served with an expired certificate")
	}
	if got := rec.got(); len(got) != 0 {
		t.Errorf("refusal counted as client failures: %v", got)
	}
}

// A file switched at runtime to ciphers that cannot carry HTTP/2, on a
// listener that offers HTTP/2 since it started, is refused (as a
// server-side failure) instead of breaking HTTP/2 clients.
func TestHTTP2CiphersCheckedAgainstListener(t *testing.T) {
	m := newMTLSTest(t, "")
	m.writeWebRaw(t, "  max_version: TLS12\n  cipher_suites:\n    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nhttp_server_config:\n  http2: false\n")
	if err := tlsGet(m.client(t, false, false), m.url()); err == nil {
		t.Error("connection accepted with ciphers the listener's HTTP/2 cannot use")
	}
	if ok, any := m.rec.lastTLSRead(); !any || ok {
		t.Errorf("not reported as a server-side failure (ok=%v)", ok)
	}
}

// Users found by a reload that keeps the listener are required from then
// on: a file losing them afterwards answers 518.
func TestUsersFoundByReloadStayRequired(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()

	basicAuthWebConfig(t, web, "prometheus", "s3cret-test")
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	writeWeb(t, dir, "web.yml", "") // truncated before any request
	if code, _ := get(t, "http://"+l.Listen+"/metrics", "", ""); code != StatusWebConfigUnreadable {
		t.Errorf("code %d, want 518", code)
	}
}

// A successful handshake that started before another one failed does not
// report the settings as healthy.
func TestTLSHealthSucceededSince(t *testing.T) {
	var reports []bool
	h := newTLSHealth(func() error { return nil }, func(ok bool) { reports = append(reports, ok) })
	gen := h.generation()
	h.failed()            // another handshake fails meanwhile
	h.succeededSince(gen) // the first one ends well
	if !slices.Equal(reports, []bool{false}) {
		t.Errorf("reports = %v, want [false]", reports)
	}
	h.succeededSince(h.generation())
	if !slices.Equal(reports, []bool{false, true}) {
		t.Errorf("reports = %v, want [false true]", reports)
	}
}

// Only the leaf's dates refuse connections: an expired intermediate (an old
// cross-signature) is skipped by clients building another path.
func TestCheckCertDatesLeafOnly(t *testing.T) {
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	good, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	expCert, expKey := filepath.Join(dir, "e.pem"), filepath.Join(dir, "e.key")
	writeExpiredServerCert(t, expCert, expKey)
	expired, err := tls.LoadX509KeyPair(expCert, expKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := tls.Certificate{Certificate: [][]byte{good.Certificate[0], expired.Certificate[0]}}
	if err := checkCertDates(&chain, time.Now()); err != nil {
		t.Errorf("expired intermediate refused: %v", err)
	}
	if err := checkCertDates(&expired, time.Now()); !errors.Is(err, errCertDates) {
		t.Errorf("expired leaf: err = %v, want errCertDates", err)
	}
	if err := checkCertDates(&good, time.Now()); err != nil {
		t.Errorf("valid certificate: %v", err)
	}
}

// A reload resetting the metrics does not hide that new TLS connections
// still fail: the next request reports it again.
func TestTLSFailureReportedAgainAfterReload(t *testing.T) {
	m := newMTLSTest(t, "")
	writeExpiredServerCert(t, m.cert, m.key)
	_ = tlsGet(m.client(t, false, false), m.url()) // fails, reported
	// The metrics reset by a reload is simulated by a healthy report.
	m.rec.WebConfigRead("node", true, true)
	if ok, _ := m.rec.lastTLSRead(); !ok {
		t.Fatal("setup: reset not recorded")
	}
	// A plain request (no TLS: the listener refuses new handshakes, so use
	// the auth handler directly) rechecks and reports the failure again.
	m.s.mu.Lock()
	auth := m.s.listeners["node"].auth
	m.s.mu.Unlock()
	auth.tlsHealth.limit = rate.NewLimiter(rate.Inf, 1)
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ok, _ := m.rec.lastTLSRead(); ok {
		t.Error("TLS failure not reported again after the reset")
	}
}

// An aborted reload raises no TLS alarm for a listener that keeps running;
// a successful one reports its failing listeners through ReportTLSHealth.
func TestTLSFailureReportedOnlyOnceApplied(t *testing.T) {
	m := newMTLSTest(t, "")
	dir := t.TempDir()
	cert, key := testTLSFiles(t, dir)
	writeExpiredServerCert(t, cert, key)
	expired := writeWeb(t, dir, "expired.yml", fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", cert, key))

	// A second listener with basic authentication.
	auth := filepath.Join(dir, "auth.yml")
	basicAuthWebConfig(t, auth, "prometheus", "s3cret-test")
	other := withAddr(t, listenerConfig("other", auth, "http://127.0.0.1:1"))
	if err := m.s.Reload(&config.Config{Listeners: []config.Listener{m.l, other}}); err != nil {
		t.Fatalf("adding a listener: %v", err)
	}
	other.Listen = m.s.Addr("other").String()

	// Aborted after the listeners are prepared: "other" would lose its
	// authentication, while "node" moves to the expired certificate.
	plain := writeWeb(t, dir, "plain.yml", "{}\n")
	moved := m.l
	moved.WebConfigFile = expired
	weakened := other
	weakened.WebConfigFile = plain
	expectWeakeningRefused(t, m.s.Reload(&config.Config{Listeners: []config.Listener{moved, weakened}}), "basic authentication")
	if ok, any := m.rec.lastTLSRead(); any && !ok {
		t.Error("aborted reload raised a TLS alarm for the running listener")
	}

	// Applied: the listener restarts on the expired certificate.
	if err := m.s.Reload(&config.Config{Listeners: []config.Listener{moved, other}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	m.s.ReportTLSHealth()
	if ok, any := m.rec.lastTLSRead(); !any || ok {
		t.Errorf("failing listener not reported after the reload (ok=%v, any=%v)", ok, any)
	}
}

// A reload re-checks the TLS settings of the listeners it keeps: a
// certificate expired without any new connection since is reported, and a
// failure fixed before the reload is no longer reported.
func TestReloadRechecksKeptListenersTLS(t *testing.T) {
	m := newMTLSTest(t, "")
	certPEM, err := os.ReadFile(m.cert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(m.key)
	if err != nil {
		t.Fatal(err)
	}
	reloadAndReport := func() {
		t.Helper()
		m.s.mu.Lock()
		before := m.s.listeners["node"]
		m.s.mu.Unlock()
		m.reload(t)
		m.s.mu.Lock()
		kept := m.s.listeners["node"] == before
		m.s.mu.Unlock()
		if !kept {
			t.Fatal("listener restarted: this test is about kept listeners")
		}
		m.rec.WebConfigRead("node", true, true) // the metrics reset by ConfigLoaded
		m.s.ReportTLSHealth()
	}

	writeExpiredServerCert(t, m.cert, m.key) // expired, no handshake since
	reloadAndReport()
	if ok, _ := m.rec.lastTLSRead(); ok {
		t.Error("expired certificate of a kept listener not reported after the reload")
	}

	writeWeb(t, filepath.Dir(m.cert), filepath.Base(m.cert), string(certPEM)) // fixed
	writeWeb(t, filepath.Dir(m.key), filepath.Base(m.key), string(keyPEM))
	reloadAndReport()
	if ok, _ := m.rec.lastTLSRead(); !ok {
		t.Error("stale TLS alarm reported after a reload that found the settings fixed")
	}
}

// A listener replaced by a reload stops reporting the web configuration
// state of its name, which its replacement reports now.
func TestReloadRetiresReplacedListener(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()
	s.mu.Lock()
	before := s.listeners["node"]
	s.mu.Unlock()

	writeWeb(t, dir, "web.yml", "rate_limit:\n  interval: 1ms\n  burst: 100\n")
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.mu.Lock()
	after := s.listeners["node"]
	s.mu.Unlock()
	if after == before {
		t.Fatal("listener not restarted")
	}
	if !before.auth.retired.Load() || after.auth.retired.Load() {
		t.Errorf("retired: replaced %v, serving %v; want true, false",
			before.auth.retired.Load(), after.auth.retired.Load())
	}
}

// Requests sent while reloads restart a listener on its socket are all
// served: a connection the previous server accepted just before stopping
// gets its response, instead of being closed (EOF) by its shutdown.
func TestReloadRestartServesEveryRequest(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()
	url := "http://" + l.Listen + "/metrics"

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var sent, failed atomic.Int64
	var firstErr atomic.Value
	for range 2 { // max_concurrent_requests default
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sent.Add(1)
				resp, err := client.Get(url)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						err = fmt.Errorf("code %d", resp.StatusCode)
					}
				}
				if err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
				}
			}
		}()
	}
	for i := range 30 {
		// A different rate_limit restarts the listener on its socket.
		writeWeb(t, dir, "web.yml", fmt.Sprintf("rate_limit:\n  interval: 1ms\n  burst: %d\n", 1000+i))
		if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Reload %d: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Errorf("%d of %d requests failed during reloads, first: %v", n, sent.Load(), firstErr.Load())
	}
}

// A listener with neither TLS nor authentication, reachable beyond this
// host, is reported at startup: an empty web configuration file serves the
// exporters to anyone.
func TestStartWarnsOnUnprotectedListener(t *testing.T) {
	dir := t.TempDir()
	empty := writeWeb(t, dir, "empty.yml", "{}\n")
	tests := []struct {
		name   string
		listen string
		warn   bool
	}{
		{"all interfaces", ":0", true},
		{"loopback only", "127.0.0.1:0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := listenerConfig("open", empty, "http://127.0.0.1:1")
			l.Listen = tt.listen
			var logs syncBuffer
			startServer(t, &config.Config{Listeners: []config.Listener{l}}, &logs)
			if got := strings.Contains(logs.String(), "anyone reaching it can read the metrics"); got != tt.warn {
				t.Errorf("warning logged = %v, want %v: %s", got, tt.warn, logs.String())
			}
		})
	}
}
