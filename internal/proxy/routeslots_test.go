package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

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
