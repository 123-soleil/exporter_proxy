package metrics

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

func testConfig() *config.Config {
	return &config.Config{
		Hash: 0xe3b0c44298fc,
		Listeners: []config.Listener{{
			Name: "node",
			Routes: []config.Route{
				{Path: "/metrics"},
				{Path: "/batch"},
			},
		}},
	}
}

func TestConfigLoaded(t *testing.T) {
	m := New()
	at := time.Unix(1_800_000_000, 0)
	m.ConfigLoaded(testConfig(), at)

	if got := testutil.ToFloat64(m.configHash); uint64(got) != 0xe3b0c44298fc {
		t.Errorf("config_hash = %v, want exactly %d", got, uint64(0xe3b0c44298fc))
	}
	if got := testutil.ToFloat64(m.reloadSuccessful); got != 1 {
		t.Errorf("config_last_reload_successful = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.reloadSuccessTstamp); got != 1_800_000_000 {
		t.Errorf("config_last_reload_success_timestamp_seconds = %v", got)
	}

	// Every reason of every route exists at 0 from the start.
	if got, want := testutil.CollectAndCount(m.sourceErrors), 2*len(reasons); got != want {
		t.Errorf("source_errors_total series = %d, want %d", got, want)
	}
	if got := testutil.CollectAndCount(m.inFlight); got != 1 {
		t.Errorf("requests_in_flight series = %d, want 1", got)
	}

	m.ConfigLoadFailed()
	if got := testutil.ToFloat64(m.reloadSuccessful); got != 0 {
		t.Errorf("after failure, config_last_reload_successful = %v, want 0", got)
	}
}

func TestRecorder(t *testing.T) {
	m := New()
	m.ConfigLoaded(testConfig(), time.Now())

	m.RequestServed("node", "/metrics", 200, 50*time.Millisecond)
	m.RequestServed("node", "/metrics", 200, 30*time.Millisecond)
	m.RequestServed("node", "/metrics", 502, time.Second)
	m.RequestServed("node", "", 404, time.Millisecond)
	m.InFlight("node", 1)
	m.InFlight("node", 1)
	m.InFlight("node", -1)
	m.RequestRejected("node")
	m.SourceRead("node", "/metrics", 4096)
	modTime := time.Unix(1_800_000_000, 500_000_000)
	m.FileModified("node", "/batch", modTime)
	m.ContentParsed("node", "/metrics", 1200, 5*time.Millisecond)
	m.SourceFailed("node", "/metrics", source.ReasonTimeout)

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"requests 200", testutil.ToFloat64(m.requests.WithLabelValues("node", "/metrics", "200")), 2},
		{"requests 502", testutil.ToFloat64(m.requests.WithLabelValues("node", "/metrics", "502")), 1},
		{"requests 404 unmatched", testutil.ToFloat64(m.requests.WithLabelValues("node", "", "404")), 1},
		{"in flight", testutil.ToFloat64(m.inFlight.WithLabelValues("node")), 1},
		{"rejected", testutil.ToFloat64(m.rejected.WithLabelValues("node")), 1},
		{"file modified", testutil.ToFloat64(m.fileModified.WithLabelValues("node", "/batch")), 1_800_000_000.5},
		{"timeout errors", testutil.ToFloat64(m.sourceErrors.WithLabelValues("node", "/metrics", "timeout")), 1},
		{"stale errors", testutil.ToFloat64(m.sourceErrors.WithLabelValues("node", "/metrics", "stale")), 0},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	// Unmatched requests do not create a duration series.
	if got := testutil.CollectAndCount(m.requestDuration); got != 1 {
		t.Errorf("request_duration_seconds series = %d, want 1 (no series for route \"\")", got)
	}
	for _, h := range []string{"exporter_proxy_parse_duration_seconds", "exporter_proxy_samples", "exporter_proxy_response_size_bytes"} {
		if n, err := testutil.GatherAndCount(m.registry, h); err != nil || n != 1 {
			t.Errorf("%s series = %d (err %v), want 1", h, n, err)
		}
	}
}

func TestHandler(t *testing.T) {
	m := New()
	m.ConfigLoaded(testConfig(), time.Now())
	h := m.Handler(slog.New(slog.DiscardHandler))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: code %d", Path, w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	for _, want := range []string{
		"exporter_proxy_build_info{",
		"exporter_proxy_config_hash ",
		"go_goroutines ",
		"process_start_time_seconds ",
		`exporter_proxy_source_errors_total{listener="node",reason="invalid",route="/batch"} 0`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics output lacks %q", want)
		}
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/other", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("GET /other: code %d, want 404", w.Code)
	}
}

// Every metric follows the naming conventions checked by promtool.
func TestMetricNamesLint(t *testing.T) {
	m := New()
	m.ConfigLoaded(testConfig(), time.Now())
	m.FileModified("node", "/batch", time.Now())
	problems, err := testutil.GatherAndLint(m.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		if strings.HasPrefix(p.Metric, "exporter_proxy_") {
			t.Errorf("%s: %s", p.Metric, p.Text)
		}
	}
}

func TestConfigReloadDeletesRemovedSeries(t *testing.T) {
	m := New()
	m.ConfigLoaded(&config.Config{Listeners: []config.Listener{
		{Name: "gone", Routes: []config.Route{{Path: "/metrics"}}},
		{Name: "kept", Routes: []config.Route{{Path: "/a"}, {Path: "/b"}}},
	}}, time.Now())
	for _, l := range []struct{ listener, route string }{{"gone", "/metrics"}, {"kept", "/a"}, {"kept", "/b"}} {
		m.RequestServed(l.listener, l.route, 200, time.Millisecond)
		m.FileModified(l.listener, l.route, time.Now())
	}
	m.RequestServed("kept", "", 404, time.Millisecond)

	// Reload: listener "gone" and route "/b" are removed.
	m.ConfigLoaded(&config.Config{Listeners: []config.Listener{
		{Name: "kept", Routes: []config.Route{{Path: "/a"}}},
	}}, time.Now())

	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "exporter_proxy_") {
			continue
		}
		for _, metric := range f.GetMetric() {
			labels := map[string]string{}
			for _, lp := range metric.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["listener"] == "gone" || labels["route"] == "/b" {
				t.Errorf("%s still has series %v after reload", f.GetName(), labels)
			}
		}
	}
	// Kept series survive, including unmatched requests of a kept listener.
	if got := testutil.ToFloat64(m.requests.WithLabelValues("kept", "/a", "200")); got != 1 {
		t.Errorf("kept series reset: %v", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("kept", "", "404")); got != 1 {
		t.Errorf("unmatched series of a kept listener reset: %v", got)
	}
}
