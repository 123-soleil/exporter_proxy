package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

func TestServiceDiscoveryEndpoint(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	dir := t.TempDir()
	web := writeWeb(t, dir, "web.yml", "{}\n")
	m := newMTLSTest(t, "") // a TLS web configuration
	plain := withAddr(t, listenerConfig("plain", web, up.URL))
	plain.Routes = append(plain.Routes, config.Route{Path: "/other/metrics", Upstream: up.URL + "/metrics", Limits: limits()})
	secure := withAddr(t, listenerConfig("secure", m.web, up.URL))
	cfg := &config.Config{
		Metrics: config.MetricsEndpoint{
			Listen: freeAddr(t), WebConfigFile: web,
			ServiceDiscovery: &config.ServiceDiscovery{Host: "node1.example.com", Labels: map[string]string{"dc": "par1"}},
		},
		Listeners: []config.Listener{plain, secure},
	}
	metricsHit := false
	s, err := Start(cfg, Options{Logger: slog.New(slog.DiscardHandler),
		MetricsHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			metricsHit = true
			_, _ = io.WriteString(w, "# metrics\n")
		})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	base := "http://" + s.Addr(MetricsListener).String()

	code, body := get(t, base+SDPath, "", "")
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", SDPath, code, body)
	}
	var groups []sdTargetGroup
	if err := json.Unmarshal([]byte(body), &groups); err != nil {
		t.Fatalf("not JSON: %v: %s", err, body)
	}
	port := func(name string) string {
		_, p, err := net.SplitHostPort(s.Addr(name).String())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	want := []struct{ target, path, scheme, listener string }{
		{"node1.example.com:" + port("plain"), "/metrics", "http", "plain"},
		{"node1.example.com:" + port("plain"), "/other/metrics", "http", "plain"},
		{"node1.example.com:" + port("secure"), "/metrics", "https", "secure"},
	}
	if len(groups) != len(want) {
		t.Fatalf("%d target groups, want %d: %s", len(groups), len(want), body)
	}
	for i, w := range want {
		g := groups[i]
		if len(g.Targets) != 1 || g.Targets[0] != w.target || g.Labels["__metrics_path__"] != w.path ||
			g.Labels["__scheme__"] != w.scheme || g.Labels["exporter_proxy_listener"] != w.listener ||
			g.Labels["exporter_proxy_route"] != w.path || g.Labels["dc"] != "par1" {
			t.Errorf("group %d = %+v, want %+v", i, g, w)
		}
	}

	// The metrics endpoint is still served.
	if code, _ := get(t, base+"/metrics", "", ""); code != http.StatusOK || !metricsHit {
		t.Errorf("/metrics: code %d, served by the metrics handler: %v", code, metricsHit)
	}
	// Other methods are refused.
	resp, err := http.Post(base+SDPath, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s: %d, want 405", SDPath, resp.StatusCode)
	}
}

// Without service_discovery, the path is not served.
func TestServiceDiscoveryDisabled(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	cfg := &config.Config{
		Metrics:   config.MetricsEndpoint{Listen: freeAddr(t), WebConfigFile: web},
		Listeners: []config.Listener{withAddr(t, listenerConfig("plain", web, up.URL))},
	}
	s, err := Start(cfg, Options{Logger: slog.New(slog.DiscardHandler), MetricsHandler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	if code, _ := get(t, "http://"+s.Addr(MetricsListener).String()+SDPath, "", ""); code != http.StatusNotFound {
		t.Errorf("code %d, want 404", code)
	}
}
