package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// A route with its own max_concurrent_requests cannot take every slot of
// the listener: slow probes of many targets leave room for other routes.
func TestRouteConcurrencyLimit(t *testing.T) {
	probe := newCountingSource()
	other := fakeSource{res: &source.Result{Body: []byte(metrics)}}
	params := map[string]config.ForwardParam{"target": {Values: []string{"a", "b"}}}
	rec := &recorder{}
	var logs bytes.Buffer
	h := newTestHandler(other, 3, rec, &logs, false)
	h.routes["/probe"] = route{path: "/probe", src: probe, maxSamples: 100, params: params, slots: routeSlots(1)}

	first := serve(h, httptest.NewRequest(http.MethodGet, "/probe?target=a", nil))
	<-probe.started
	// Another target: a read of its own, refused by the route limit.
	if w := <-serve(h, httptest.NewRequest(http.MethodGet, "/probe?target=b", nil)); w.Code != http.StatusServiceUnavailable {
		t.Errorf("second target: code %d, want 503", w.Code)
	}
	if !bytes.Contains(logs.Bytes(), []byte("limit_of=route")) {
		t.Errorf("rejection not attributed to the route: %s", logs.String())
	}
	// Other routes still have listener slots (the refused read gave its
	// listener slot back).
	for range 2 {
		if w := get(h); w.Code != http.StatusOK {
			t.Errorf("other route: code %d, want 200", w.Code)
		}
	}
	close(probe.release)
	if w := <-first; w.Code != http.StatusOK {
		t.Errorf("first target: code %d", w.Code)
	}
	// Both slots are free again.
	if w := <-serve(h, httptest.NewRequest(http.MethodGet, "/probe?target=b", nil)); w.Code != http.StatusOK {
		t.Errorf("after release: code %d, want 200", w.Code)
	}
	if rec.inFlight != 0 {
		t.Errorf("in flight %d, want 0", rec.inFlight)
	}
}

func TestHandlerMetricsFilter(t *testing.T) {
	src := fakeSource{res: &source.Result{Body: []byte("# TYPE secret_token gauge\nsecret_token 1\n# TYPE up gauge\nup 1\n")}}
	cfg, err := config.Parse([]byte(`metrics:
  listen: "127.0.0.1:9999"
  web_config_file: /etc/ep/web.yml
listeners:
  - name: a
    listen: ":9100"
    web_config_file: /etc/ep/web.yml
    routes:
      - path: /metrics
        upstream: http://h/m
        metrics_filter:
          deny: ['secret_.*']
`))
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100,
		filter: cfg.Listeners[0].Routes[0].MetricsFilter}}, 2, Options{})
	w := get(h)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "up 1") {
		t.Errorf("code %d body %q", w.Code, w.Body.String())
	}
}

// slowWriter blocks the body write until released, like a client reading
// slowly.
type slowWriter struct {
	*httptest.ResponseRecorder
	writing chan struct{}
	release chan struct{}
}

func (w *slowWriter) Write(b []byte) (int, error) {
	close(w.writing)
	<-w.release
	return w.ResponseRecorder.Write(b)
}

// A read keeps its slot until its answer is written: slow clients cannot
// make the proxy hold more answers in memory than max_concurrent_requests.
func TestSlotHeldWhileTheAnswerIsWritten(t *testing.T) {
	src := fakeSource{res: &source.Result{Body: []byte(metrics)}}
	rec := &recorder{}
	h := newTestHandler(src, 1, rec, &bytes.Buffer{}, false)
	slow := &slowWriter{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(slow, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		close(done)
	}()
	<-slow.writing
	if w := get(h); w.Code != http.StatusServiceUnavailable {
		t.Errorf("while an answer is being written: code %d, want 503", w.Code)
	}
	close(slow.release)
	<-done
	if w := get(h); w.Code != http.StatusOK {
		t.Errorf("after: code %d, want 200", w.Code)
	}
	if rec.inFlight != 0 {
		t.Errorf("in flight %d, want 0", rec.inFlight)
	}
}

func TestWriteTime(t *testing.T) {
	for _, tt := range []struct {
		size    int
		timeout time.Duration
		want    time.Duration
	}{
		{0, 10 * time.Second, 5 * time.Second},
		{1 << 20, 10 * time.Second, 7 * time.Second},
		{8 << 20, 10 * time.Second, 20 * time.Second}, // capped: route timeout + margin
		{8 << 20, 0, 21 * time.Second},
	} {
		if got := writeTime(tt.size, tt.timeout); got != tt.want {
			t.Errorf("writeTime(%d, %s) = %s, want %s", tt.size, tt.timeout, got, tt.want)
		}
	}
}
