package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

// countingFetch counts reads and fails while fail is set.
type countingFetch struct {
	reads atomic.Int32
	fail  atomic.Bool
}

func (c *countingFetch) Fetch(context.Context, source.Request) (*source.Result, error) {
	c.reads.Add(1)
	if c.fail.Load() {
		return nil, &source.Error{Reason: source.ReasonUnavailable, Err: errors.New("down")}
	}
	return &source.Result{Body: []byte(metrics)}, nil
}

func cachedHandler(src source.Source, ttl time.Duration, rec *recorder) *Handler {
	return newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100, cacheTTL: ttl}}, 2,
		Options{Recorder: rec})
}

func get(h http.Handler) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return w
}

func TestCacheServesWithinTTL(t *testing.T) {
	src := &countingFetch{}
	rec := &recorder{}
	h := cachedHandler(src, time.Hour, rec)
	for i := range 3 {
		w := get(h)
		if w.Code != http.StatusOK || w.Body.String() != metrics {
			t.Fatalf("request %d: %d %q", i, w.Code, w.Body.String())
		}
		if w.Header().Get("Age") == "" {
			t.Errorf("request %d: no Age header", i)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("request %d: Cache-Control %q", i, w.Header().Get("Cache-Control"))
		}
	}
	if n := src.reads.Load(); n != 1 {
		t.Errorf("%d source reads, want 1", n)
	}
	if rec.cacheHits != 2 {
		t.Errorf("cache hits %d, want 2", rec.cacheHits)
	}
}

func TestCacheExpires(t *testing.T) {
	src := &countingFetch{}
	h := cachedHandler(src, 20*time.Millisecond, &recorder{})
	get(h)
	time.Sleep(40 * time.Millisecond)
	get(h)
	if n := src.reads.Load(); n != 2 {
		t.Errorf("%d source reads, want 2 (expired)", n)
	}
}

// Failures are never cached: the next request reads again.
func TestCacheKeepsOnlySuccesses(t *testing.T) {
	src := &countingFetch{}
	src.fail.Store(true)
	h := cachedHandler(src, time.Hour, &recorder{})
	if w := get(h); w.Code != http.StatusBadGateway {
		t.Fatalf("code %d", w.Code)
	}
	src.fail.Store(false)
	if w := get(h); w.Code != http.StatusOK {
		t.Errorf("after recovery: code %d", w.Code)
	}
	if n := src.reads.Load(); n != 2 {
		t.Errorf("%d source reads, want 2", n)
	}
}

// Without cache_ttl, every request reads.
func TestNoCacheByDefault(t *testing.T) {
	src := &countingFetch{}
	h := cachedHandler(src, 0, &recorder{})
	get(h)
	w := get(h)
	if n := src.reads.Load(); n != 2 {
		t.Errorf("%d source reads, want 2", n)
	}
	if w.Header().Get("Age") != "" {
		t.Error("Age header without cache")
	}
}

// orderedSource blocks each read until its own release, in call order.
type orderedSource struct {
	mu       sync.Mutex
	calls    int
	started  chan int
	releases []chan struct{}
}

func newOrderedSource(n int) *orderedSource {
	o := &orderedSource{started: make(chan int, n)}
	for range n {
		o.releases = append(o.releases, make(chan struct{}))
	}
	return o
}

func (o *orderedSource) Fetch(ctx context.Context, _ source.Request) (*source.Result, error) {
	o.mu.Lock()
	n := o.calls
	o.calls++
	o.mu.Unlock()
	o.started <- n
	select {
	case <-o.releases[n]:
		return &source.Result{Body: []byte(metrics)}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func budgetReq(header string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if header != "" {
		req.Header.Set(scrapeTimeoutHeader, header)
	}
	return req
}

// A short-timeout read finishing last does not replace the fresh cached
// answer of a read told the route timeout.
func TestCacheKeepsTheMoreUsefulEntry(t *testing.T) {
	src := newOrderedSource(2)
	h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100, cacheTTL: time.Hour,
		timeout: 10 * time.Second}}, 2, Options{Recorder: &recorder{}})
	short := serve(h, budgetReq("3")) // read 0, told 2.5s
	<-src.started
	long := serve(h, budgetReq("")) // read 1 of its own, told the route timeout
	<-src.started
	close(src.releases[1])
	<-long
	close(src.releases[0])
	<-short
	h.mu.Lock()
	entry := h.cache["/metrics"]
	h.mu.Unlock()
	if entry == nil {
		t.Fatal("nothing cached")
	}
	if entry.advertised != 0 {
		t.Errorf("cache entry advertised %v, want the route timeout's (0)", entry.advertised)
	}
}

// With no slot free, a request gets a cached answer it would not have
// shared, rather than 503.
func TestCacheServedRatherThanRefused(t *testing.T) {
	cachedSrc := &countingFetch{}
	busy := newCountingSource()
	h := newHandler("test", []route{
		{path: "/metrics", src: cachedSrc, maxSamples: 100, cacheTTL: time.Hour, timeout: 10 * time.Second},
		{path: "/other", src: busy, maxSamples: 100},
	}, 1, Options{Recorder: &recorder{}})
	h.ServeHTTP(httptest.NewRecorder(), budgetReq("2")) // cached, told 1.5s
	other := serve(h, httptest.NewRequest(http.MethodGet, "/other", nil))
	<-busy.started // the only slot is taken
	w := httptest.NewRecorder()
	h.ServeHTTP(w, budgetReq(""))
	if w.Code != http.StatusOK {
		t.Errorf("code %d, want 200 from the cache", w.Code)
	}
	close(busy.release)
	<-other
}
