package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
)

// getErr sends a request without keep-alive and returns its status code or
// the error.
func getErr(url string) (int, error) {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestAllowedNetworks(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	l.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	rec := &authRecorder{}
	logs := &syncBuffer{}
	s, err := Start(&config.Config{Listeners: []config.Listener{l}},
		Options{Logger: slog.New(slog.NewTextHandler(logs, nil)), Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	url := "http://" + s.Addr("node").String() + "/metrics"

	// 127.0.0.1 is outside 192.0.2.0/24: the connection is closed before
	// any request.
	if code, err := getErr(url); err == nil {
		t.Fatalf("request from a refused address answered %d", code)
	}
	if !slices.Contains(rec.got(), proxy.AuthNetworkNotAllowed) {
		t.Errorf("refusal not recorded: %v", rec.got())
	}
	if !strings.Contains(logs.String(), "client address not in allowed_networks") ||
		!strings.Contains(logs.String(), "remote=127.0.0.1") {
		t.Errorf("refusal not logged with the client address: %s", logs.String())
	}

	// A reload allowing the address applies without restarting the
	// listener.
	s.mu.Lock()
	before := s.listeners["node"]
	s.mu.Unlock()
	l.Listen = s.Addr("node").String()
	l.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("127.0.0.0/8")}
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	after := s.listeners["node"]
	s.mu.Unlock()
	if after != before {
		t.Error("listener restarted to apply allowed_networks")
	}
	if code, err := getErr(url); err != nil || code != http.StatusOK {
		t.Errorf("allowed address after reload: code %d, err %v", code, err)
	}

	// Removing allowed_networks allows every address.
	l.AllowedNetworks = nil
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatal(err)
	}
	if code, err := getErr(url); err != nil || code != http.StatusOK {
		t.Errorf("without allowed_networks: code %d, err %v", code, err)
	}
}

func TestAllowsAddresses(t *testing.T) {
	l := &listener{}
	allowed := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}
	l.allowed.Store(&allowed)
	tests := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3:4000", true},
		{"[::ffff:10.1.2.3]:4000", true}, // IPv4-mapped, as dual-stack sockets report
		{"11.0.0.1:4000", false},
		{"[2001:db8::1]:4000", true},
		{"[2001:db9::1]:4000", false},
		{"[fe80::1%eth0]:4000", false},
		{"unix", false}, // unparseable: refused
	}
	for _, tt := range tests {
		var addr net.Addr = unixRemote{}
		if tt.addr != "unix" {
			addr = net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tt.addr))
		}
		if got := l.allows(addr); got != tt.want {
			t.Errorf("allows(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	var none []netip.Prefix
	l.allowed.Store(&none)
	if !l.allows(unixRemote{}) {
		t.Error("without allowed_networks, every address must be allowed")
	}
}

// allowed_networks cannot be checked for Unix socket clients: such a
// listener does not start.
func TestAllowedNetworksRefusedOnUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "anu") // short path: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	s := &Server{logger: slog.New(slog.DiscardHandler), successes: map[string]*successCache{}}
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	_, err = s.newListener(spec{name: "u", listen: "systemd:u", webConfig: web, handler: http.NotFoundHandler(),
		allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, ln)
	if err == nil || !strings.Contains(err.Error(), "Unix socket") {
		t.Errorf("err = %v, want a refusal for the Unix socket", err)
	}
}

// A reload narrowing allowed_networks refuses, at their next request,
// the connections opened before it, and closes them.
func TestAllowedNetworksReloadRefusesOpenConnections(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	l.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	rec := &authRecorder{}
	s, err := Start(&config.Config{Listeners: []config.Listener{l}},
		Options{Logger: slog.New(slog.DiscardHandler), Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	l.Listen = s.Addr("node").String()

	conn, err := net.Dial("tcp", l.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	send := func() *http.Response {
		t.Helper()
		if _, err := io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	if resp := send(); resp.StatusCode != http.StatusOK {
		t.Fatalf("before the reload: code %d", resp.StatusCode)
	}

	l.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatal(err)
	}
	resp := send() // same connection
	if resp.StatusCode != http.StatusForbidden || !resp.Close {
		t.Errorf("after the reload: code %d, close %v; want 403 and the connection closed", resp.StatusCode, resp.Close)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Error("connection still open")
	}
	if !slices.Contains(rec.got(), proxy.AuthNetworkNotAllowed) {
		t.Errorf("refusal not recorded: %v", rec.got())
	}
}

// keepAliveConn sends requests on one HTTP/1.1 connection.
type keepAliveConn struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialKeepAlive(t *testing.T, addr string) *keepAliveConn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &keepAliveConn{t: t, conn: conn, br: bufio.NewReader(conn)}
}

// holdDrain opens a connection that sends nothing: a server being drained
// waits for it (up to readHeaderTimeout) before shutting down, which keeps
// the window where it still answers open connections.
func holdDrain(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func (k *keepAliveConn) get(path string) int {
	k.t.Helper()
	if _, err := io.WriteString(k.conn, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		k.t.Fatal(err)
	}
	resp, err := http.ReadResponse(k.br, nil)
	if err != nil {
		k.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A reload restarting a listener on its socket: connections opened to the
// previous server get the new allowed_networks until it shuts down.
func TestRestartedListenerAppliesNewSettingsToOpenConnections(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()
	k := dialKeepAlive(t, l.Listen)
	if code := k.get("/metrics"); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}
	holdDrain(t, l.Listen)
	time.Sleep(50 * time.Millisecond) // accepted by the current server
	// rate_limit restarts the listener; allowed_networks now excludes us.
	writeWeb(t, dir, "web.yml", "rate_limit:\n  interval: 1ms\n  burst: 100\n")
	l.AllowedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s.mu.Lock()
	before := s.listeners["node"]
	s.mu.Unlock()
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	after := s.listeners["node"]
	s.mu.Unlock()
	if after == before {
		t.Fatal("listener not restarted")
	}
	if code := k.get("/metrics"); code != http.StatusForbidden {
		t.Errorf("open connection to the previous server: code %d, want 403", code)
	}
}

// A listener removed by a reload no longer serves its routes on
// connections opened before.
func TestRemovedListenerStopsServingOpenConnections(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	keep := withAddr(t, listenerConfig("keep", web, up.URL))
	gone := withAddr(t, listenerConfig("gone", web, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{keep, gone}}, io.Discard)
	keep.Listen = s.Addr("keep").String()
	k := dialKeepAlive(t, s.Addr("gone").String())
	if code := k.get("/metrics"); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}
	holdDrain(t, s.Addr("gone").String())
	time.Sleep(50 * time.Millisecond)
	if err := s.Reload(&config.Config{Listeners: []config.Listener{keep}}); err != nil {
		t.Fatal(err)
	}
	if code := k.get("/metrics"); code != http.StatusServiceUnavailable {
		t.Errorf("open connection to the removed listener: code %d, want 503", code)
	}
}

// A listener replaced on its address by one with another web
// configuration file: connections opened to the previous server, still
// behind its authentication, must not reach the new routes.
func TestReplacedListenerWithOtherWebConfigServesNothing(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	open := writeWeb(t, dir, "open.yml", "{}\n")
	locked := writeWeb(t, dir, "locked.yml", usersYAML(t, map[string]string{"u": "pw"}))
	l := withAddr(t, listenerConfig("node", open, up.URL))
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	addr := s.Addr("node").String()
	k := dialKeepAlive(t, addr)
	if code := k.get("/metrics"); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}
	holdDrain(t, addr)
	time.Sleep(50 * time.Millisecond)

	renamed := listenerConfig("renamed", locked, up.URL)
	renamed.Listen = addr
	renamed.Routes[0].Path = "/secret"
	if err := s.Reload(&config.Config{Listeners: []config.Listener{renamed}}); err != nil {
		t.Fatal(err)
	}
	if code := k.get("/secret"); code == http.StatusOK {
		t.Fatal("new route served without its authentication on a connection to the previous server")
	} else if code != http.StatusServiceUnavailable {
		t.Errorf("code %d, want 503", code)
	}
	// A new connection gets the new authentication.
	if code, _ := get(t, "http://"+addr+"/secret", "", ""); code != http.StatusUnauthorized {
		t.Errorf("new connection without credentials: code %d, want 401", code)
	}
}
