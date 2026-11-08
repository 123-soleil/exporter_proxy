package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// countingSource blocks every read until released, and counts reads and
// canceled reads.
type countingSource struct {
	started  chan struct{}
	release  chan struct{}
	reads    atomic.Int32
	canceled atomic.Int32
}

func newCountingSource() *countingSource {
	return &countingSource{started: make(chan struct{}, 10), release: make(chan struct{})}
}

func (c *countingSource) Fetch(ctx context.Context) (*source.Result, error) {
	c.reads.Add(1)
	c.started <- struct{}{}
	select {
	case <-c.release:
		return &source.Result{Body: []byte(metrics)}, nil
	case <-ctx.Done():
		c.canceled.Add(1)
		return nil, ctx.Err()
	}
}

// serve runs a request in the background and returns its recorder once
// done.
func serve(h http.Handler, req *http.Request) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		done <- w
	}()
	return done
}

// waitShared waits until n requests joined a running read.
func waitShared(t *testing.T, rec *recorder, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec.mu.Lock()
		got := rec.shared
		rec.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d requests shared a read, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Concurrent requests of a route share one source read, and only that read
// takes a concurrency slot.
func TestConcurrentRequestsShareOneRead(t *testing.T) {
	src := newCountingSource()
	rec := &recorder{}
	h := newTestHandler(src, 1, rec, &bytes.Buffer{}, false) // a single slot
	first := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	<-src.started
	others := []<-chan *httptest.ResponseRecorder{
		serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil)),
		serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil)),
	}
	waitShared(t, rec, 2)
	close(src.release)
	for i, done := range append(others, first) {
		w := <-done
		if w.Code != http.StatusOK || w.Body.String() != metrics {
			t.Errorf("request %d: code %d, body %q", i, w.Code, w.Body.String())
		}
	}
	if n := src.reads.Load(); n != 1 {
		t.Errorf("%d source reads, want 1", n)
	}
	if rec.rejected != 0 {
		t.Errorf("%d requests rejected: shared requests must not take a slot", rec.rejected)
	}
	if len(rec.reads) != 1 || len(rec.parsed) != 1 {
		t.Errorf("source read recorded %d times, parsed %d times, want 1", len(rec.reads), len(rec.parsed))
	}
}

// The read goes on when the request that started it leaves while another
// one waits for it.
func TestSharedReadSurvivesTheFirstClientLeaving(t *testing.T) {
	src := newCountingSource()
	rec := &recorder{}
	h := newTestHandler(src, 1, rec, &bytes.Buffer{}, false)
	ctx, cancel := context.WithCancel(context.Background())
	first := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx))
	<-src.started
	second := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	waitShared(t, rec, 1)
	cancel()
	if w := <-first; w.Code != http.StatusBadGateway {
		t.Errorf("first request: code %d, want 502 (recorded as 499)", w.Code)
	}
	close(src.release)
	if w := <-second; w.Code != http.StatusOK {
		t.Errorf("second request: code %d, want 200", w.Code)
	}
	if src.canceled.Load() != 0 {
		t.Error("read canceled although a request still waited for it")
	}
}

// A read nobody waits for any more is canceled and frees its slot: clients
// leaving at once cannot hold the slots until the route timeout.
func TestSharedReadCanceledWhenEveryClientLeft(t *testing.T) {
	src := newCountingSource()
	h := newTestHandler(src, 1, &recorder{}, &bytes.Buffer{}, false)
	ctx, cancel := context.WithCancel(context.Background())
	first := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx))
	<-src.started
	cancel()
	<-first
	// The read runs on its own: it sees the cancellation shortly after.
	deadline := time.Now().Add(5 * time.Second)
	for src.canceled.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("read not canceled after its only client left")
		}
		time.Sleep(time.Millisecond)
	}
	// The slot is free: a new request starts a new read.
	next := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	<-src.started
	close(src.release)
	if w := <-next; w.Code != http.StatusOK {
		t.Errorf("next request: code %d, want 200", w.Code)
	}
}

// A request joining a read keeps its own scrape budget.
func TestSharedReadHonorsTheWaitingRequestBudget(t *testing.T) {
	src := newCountingSource()
	h := newTestHandler(src, 1, &recorder{}, &bytes.Buffer{}, false)
	first := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	<-src.started
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(scrapeTimeoutHeader, "1") // budget: minScrapeBudget
	start := time.Now()
	w := <-serve(h, req)
	if w.Code != http.StatusBadGateway || !bytes.Contains(w.Body.Bytes(), []byte("timeout")) {
		t.Errorf("code %d, body %q: want 502 timeout", w.Code, w.Body.String())
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("waited %s, budget is %s", d, minScrapeBudget)
	}
	close(src.release)
	<-first
}

// Requests of different routes do not share reads.
func TestReadsNotSharedAcrossRoutes(t *testing.T) {
	a, b := newCountingSource(), newCountingSource()
	h := newHandler("test", []route{
		{path: "/a", src: a, maxSamples: 100},
		{path: "/b", src: b, maxSamples: 100},
	}, 2, Options{Recorder: &recorder{}})
	var wg sync.WaitGroup
	for _, p := range []string{"/a", "/b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
		}()
	}
	<-a.started
	<-b.started
	close(a.release)
	close(b.release)
	wg.Wait()
	if a.reads.Load() != 1 || b.reads.Load() != 1 {
		t.Errorf("reads: /a %d, /b %d, want 1 each", a.reads.Load(), b.reads.Load())
	}
}

// A request starting a read with a short budget does not cut it short for
// a request joining it with a longer one.
func TestSharedReadOutlivesTheStarterBudget(t *testing.T) {
	src := newCountingSource()
	rec := &recorder{}
	h := newTestHandler(src, 1, rec, &bytes.Buffer{}, false)
	short := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	short.Header.Set(scrapeTimeoutHeader, "0.1") // budget: minScrapeBudget
	first := serve(h, short)
	<-src.started
	second := serve(h, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	waitShared(t, rec, 1)
	if w := <-first; w.Code != http.StatusBadGateway {
		t.Errorf("short budget: code %d, want 502 timeout", w.Code)
	}
	close(src.release) // after the first request's budget
	if w := <-second; w.Code != http.StatusOK {
		t.Errorf("joining request: code %d, want 200", w.Code)
	}
	if src.canceled.Load() != 0 {
		t.Error("read canceled by the first request's budget")
	}
}

// panicSource panics while reading.
type panicSource struct{}

func (panicSource) Fetch(context.Context) (*source.Result, error) { panic("boom") }

// A panic while reading fails the request instead of the process.
func TestSharedReadRecoversFromPanics(t *testing.T) {
	var logs bytes.Buffer
	h := newTestHandler(panicSource{}, 1, &recorder{}, &logs, false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusBadGateway || w.Body.String() != "source rejected: unavailable\n" {
		t.Errorf("code %d body %q, want 502 unavailable", w.Code, w.Body.String())
	}
	if !bytes.Contains(logs.Bytes(), []byte("panic while reading the source")) {
		t.Errorf("panic not logged: %s", logs.String())
	}
	// The slot was released.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusBadGateway {
		t.Errorf("second request: code %d", w.Code)
	}
}
