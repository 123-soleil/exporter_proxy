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
				{Path: "/batch", File: "/var/lib/batch.prom"},
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
		{"in flight", float64(m.inFlight.value("node")), 1},
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

// Requests of a removed listener that are still draining do not bring its
// series back, and the in-flight count stays right if it is added back.
func TestRemovedListenerSeriesStayDeleted(t *testing.T) {
	m := New()
	node := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{{Path: "/metrics"}}}}}
	other := &config.Config{Listeners: []config.Listener{{Name: "other", Routes: []config.Route{{Path: "/metrics"}}}}}
	m.ConfigLoaded(node, time.Now())
	m.InFlight("node", 1) // a request starts

	m.ConfigLoaded(other, time.Now()) // "node" removed while the request runs
	m.SourceFailed("node", "/metrics", source.ReasonTimeout)
	m.RequestServed("node", "/metrics", 502, time.Second)
	m.AuthFailed("node", "rate_limited")

	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "listener" && lp.GetValue() == "node" {
					t.Errorf("%s: series of removed listener recreated", f.GetName())
				}
			}
		}
	}

	m.ConfigLoaded(node, time.Now()) // added back before the request ends
	m.InFlight("node", -1)           // the old request ends
	if got := m.inFlight.value("node"); got != 0 {
		t.Errorf("in flight = %d after the request ended, want 0", got)
	}
	if n := testutil.CollectAndCount(m.inFlight); n != 1 {
		t.Errorf("requests_in_flight series = %d, want 1", n)
	}
}

// A route that stops being a file route loses its modification time series.
func TestFileModifiedDeletedWhenRouteChangesSource(t *testing.T) {
	m := New()
	file := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{{Path: "/m", File: "/var/m.prom"}}}}}
	upstream := &config.Config{Listeners: []config.Listener{{Name: "node", Routes: []config.Route{{Path: "/m", Upstream: "http://h/m"}}}}}
	m.ConfigLoaded(file, time.Now())
	m.FileModified("node", "/m", time.Now())
	m.RequestServed("node", "/m", 200, time.Millisecond)

	m.ConfigLoaded(upstream, time.Now())
	if n := testutil.CollectAndCount(m.fileModified); n != 0 {
		t.Errorf("file_modified_timestamp_seconds series = %d after the route became HTTP, want 0", n)
	}
	// A file read still running on the replaced handler ends now.
	m.FileModified("node", "/m", time.Now())
	if n := testutil.CollectAndCount(m.fileModified); n != 0 {
		t.Errorf("late file read recreated the series (%d series)", n)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("node", "/m", "200")); got != 1 {
		t.Errorf("other series of the route reset: %v", got)
	}
}

func TestWebConfigReadError(t *testing.T) {
	m := New()
	m.ConfigLoaded(testConfig(), time.Now())
	// One series per listener plus the metrics endpoint, at 0 from the start.
	if n := testutil.CollectAndCount(m.webConfigError); n != 2 {
		t.Errorf("web_config_read_error series = %d, want 2", n)
	}

	m.WebConfigRead("node", false)
	if got := testutil.ToFloat64(m.webConfigError.WithLabelValues("node")); got != 1 {
		t.Errorf("after a failed read = %v, want 1", got)
	}
	m.WebConfigRead("node", true)
	if got := testutil.ToFloat64(m.webConfigError.WithLabelValues("node")); got != 0 {
		t.Errorf("after a successful read = %v, want 0", got)
	}

	m.WebConfigRead("unknown", false) // not configured: not recorded
	if n := testutil.CollectAndCount(m.webConfigError); n != 2 {
		t.Errorf("series for an unconfigured listener created (%d series)", n)
	}
}
