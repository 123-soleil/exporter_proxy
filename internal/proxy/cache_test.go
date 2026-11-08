package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
