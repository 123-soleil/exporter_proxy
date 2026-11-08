package check

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

func TestProbe(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = fmt.Fprint(w, "# TYPE up gauge\nup 1\n")
		case "/many":
			_, _ = fmt.Fprint(w, strings.Repeat("x 1\n", 9))
		default:
			_, _ = fmt.Fprint(w, "<html>login page</html>")
		}
	}))
	defer up.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "m.prom")
	writeFile(t, file, "# TYPE batch gauge\nbatch 1\n")
	limits := config.Limits{Timeout: 2 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 10}
	cfg := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{
		{Path: "/ok", Upstream: up.URL + "/ok", Limits: limits},
		{Path: "/html", Upstream: up.URL + "/html", Limits: limits},
		{Path: "/many", Upstream: up.URL + "/many", Limits: limits},
		{Path: "/down", Upstream: "http://127.0.0.1:1/metrics", Limits: limits},
		{Path: "/file", File: file, MaxAge: time.Hour, Limits: limits},
		{Path: "/probe", Upstream: up.URL + "/ok", Limits: limits,
			ForwardParams: map[string]config.ForwardParam{"target": {Values: []string{"x"}, Required: true}}},
	}}}}
	expect(t, Probe(context.Background(), cfg),
		want{Problem, `route "/html": probe: invalid`},
		want{Warning, `route "/many": probe: 9 samples, close to max_samples (10)`},
		want{Problem, `route "/down": probe: unavailable`},
		want{Warning, `route "/probe": not probed: it needs the query parameter "target"`})
}

// Interrupted probes stop with one finding, not a failure per route.
func TestProbeInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	limits := config.Limits{Timeout: time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 10}
	cfg := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{
		{Path: "/a", Upstream: "http://127.0.0.1:1/a", Limits: limits},
		{Path: "/b", Upstream: "http://127.0.0.1:1/b", Limits: limits},
	}}}}
	expect(t, Probe(ctx, cfg), want{Problem, "interrupted"})
}

// A signal during a read reports it as interrupted, not as a failure.
func TestProbeInterruptedDuringRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer up.Close()
	limits := config.Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 10}
	cfg := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{
		{Path: "/last", Upstream: up.URL + "/m", Limits: limits},
	}}}}
	expect(t, Probe(ctx, cfg), want{Problem, "interrupted"})
}
