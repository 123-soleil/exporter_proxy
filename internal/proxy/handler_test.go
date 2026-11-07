package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

const metrics = "# TYPE up gauge\nup 1\n"

// fakeSource returns a fixed result.
type fakeSource struct {
	res *source.Result
	err error
}

func (f fakeSource) Fetch(context.Context) (*source.Result, error) { return f.res, f.err }

// blockingSource waits until released, to hold concurrency slots.
type blockingSource struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingSource) Fetch(ctx context.Context) (*source.Result, error) {
	b.started <- struct{}{}
	select {
	case <-b.release:
		return &source.Result{Body: []byte(metrics)}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// recorder captures Recorder events.
type recorder struct {
	mu       sync.Mutex
	served   []string // "route code"
	rejected int
	inFlight int
	maxIn    int
	reads    []int
	modTimes []time.Time
	parsed   []int
	failed   []source.Reason
}

func (r *recorder) RequestServed(_, route string, code int, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.served = append(r.served, fmt.Sprintf("%s %d", route, code))
}

func (r *recorder) InFlight(_ string, delta int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inFlight += delta
	if r.inFlight > r.maxIn {
		r.maxIn = r.inFlight
	}
}

func (r *recorder) RequestRejected(string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected++
}

func (r *recorder) SourceRead(_, _ string, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads = append(r.reads, size)
}

func (r *recorder) FileModified(_, _ string, t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modTimes = append(r.modTimes, t)
}

func (r *recorder) ContentParsed(_, _ string, samples int, _ time.Duration, _ bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsed = append(r.parsed, samples)
}

func (r *recorder) AuthFailed(string, AuthReason) {}

func (r *recorder) WebConfigRead(string, bool, bool) {}

func (r *recorder) SourceFailed(_, _ string, reason source.Reason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = append(r.failed, reason)
}

func newTestHandler(src source.Source, maxConcurrent int, rec *recorder, logs *bytes.Buffer, access bool) *Handler {
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100}}, maxConcurrent,
		Options{Logger: logger, Recorder: rec, AccessLog: access})
}

func TestHandler(t *testing.T) {
	modTime := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 101; i++ { // maxSamples is 100 in newTestHandler
		fmt.Fprintf(&b, "n{i=\"%d\"} 1\n", i)
	}
	tooMany := b.String()

	tests := []struct {
		name       string
		method     string
		path       string
		src        source.Source
		wantCode   int
		wantBody   string // exact for 200, substring otherwise
		wantFailed []source.Reason
		wantServed string
		wantLog    string
	}{
		{
			name:       "get",
			method:     http.MethodGet,
			path:       "/metrics",
			src:        fakeSource{res: &source.Result{Body: []byte(metrics)}},
			wantCode:   http.StatusOK,
			wantBody:   metrics,
			wantServed: "/metrics 200",
		},
		{
			name:       "head",
			method:     http.MethodHead,
			path:       "/metrics",
			src:        fakeSource{res: &source.Result{Body: []byte(metrics)}},
			wantCode:   http.StatusOK,
			wantBody:   "",
			wantServed: "/metrics 200",
		},
		{
			name:       "query string ignored for routing",
			method:     http.MethodGet,
			path:       "/metrics?x=1",
			src:        fakeSource{res: &source.Result{Body: []byte(metrics)}},
			wantCode:   http.StatusOK,
			wantBody:   metrics,
			wantServed: "/metrics 200",
		},
		{
			name:       "unknown path",
			method:     http.MethodGet,
			path:       "/other",
			src:        fakeSource{},
			wantCode:   http.StatusNotFound,
			wantServed: " 404",
		},
		{
			name:       "path is exact",
			method:     http.MethodGet,
			path:       "/metrics/",
			src:        fakeSource{},
			wantCode:   http.StatusNotFound,
			wantServed: " 404",
		},
		{
			name:       "post",
			method:     http.MethodPost,
			path:       "/metrics",
			src:        fakeSource{},
			wantCode:   http.StatusMethodNotAllowed,
			wantServed: "/metrics 405",
		},
		{
			name:       "source unavailable",
			method:     http.MethodGet,
			path:       "/metrics",
			src:        fakeSource{err: source.NewError(source.ReasonUnavailable, "dial unix /run/secret/path.sock: refused")},
			wantCode:   http.StatusBadGateway,
			wantBody:   "source rejected: unavailable",
			wantFailed: []source.Reason{source.ReasonUnavailable},
			wantServed: "/metrics 502",
			wantLog:    "/run/secret/path.sock",
		},
		{
			name:       "stale file",
			method:     http.MethodGet,
			path:       "/metrics",
			src:        fakeSource{res: &source.Result{ModTime: modTime}, err: source.NewError(source.ReasonStale, "old")},
			wantCode:   http.StatusBadGateway,
			wantBody:   "source rejected: stale",
			wantFailed: []source.Reason{source.ReasonStale},
			wantServed: "/metrics 502",
		},
		{
			name:       "invalid content",
			method:     http.MethodGet,
			path:       "/metrics",
			src:        fakeSource{res: &source.Result{Body: []byte("<html></html>\n")}},
			wantCode:   http.StatusBadGateway,
			wantBody:   "source rejected: invalid",
			wantFailed: []source.Reason{source.ReasonInvalid},
			wantServed: "/metrics 502",
		},
		{
			name:       "too many samples",
			method:     http.MethodGet,
			path:       "/metrics",
			src:        fakeSource{res: &source.Result{Body: []byte(tooMany)}},
			wantCode:   http.StatusBadGateway,
			wantBody:   "source rejected: too_many_samples",
			wantFailed: []source.Reason{source.ReasonTooManySamples},
			wantServed: "/metrics 502",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			var logs bytes.Buffer
			h := newTestHandler(tt.src, 2, rec, &logs, false)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			if w.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", w.Code, tt.wantCode)
			}
			body := w.Body.String()
			if tt.wantCode == http.StatusOK {
				if body != tt.wantBody {
					t.Errorf("body = %q, want %q", body, tt.wantBody)
				}
				if ct := w.Header().Get("Content-Type"); ct != contentType {
					t.Errorf("Content-Type = %q", ct)
				}
				if cl := w.Header().Get("Content-Length"); cl != fmt.Sprint(len(metrics)) {
					t.Errorf("Content-Length = %q", cl)
				}
			} else if !strings.Contains(body, tt.wantBody) {
				t.Errorf("body = %q, want substring %q", body, tt.wantBody)
			}
			if strings.Contains(body, "/run/secret") {
				t.Errorf("error details leaked to the client: %q", body)
			}
			if tt.wantCode == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("Allow = %q", w.Header().Get("Allow"))
			}

			if fmt.Sprint(rec.failed) != fmt.Sprint(tt.wantFailed) {
				t.Errorf("failed reasons = %v, want %v", rec.failed, tt.wantFailed)
			}
			if len(rec.served) != 1 || rec.served[0] != tt.wantServed {
				t.Errorf("served = %q, want [%q]", rec.served, tt.wantServed)
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs = %q, want substring %q", logs.String(), tt.wantLog)
			}
			if tt.wantCode == http.StatusOK && logs.Len() > 0 {
				t.Errorf("successful request logged without access log: %q", logs.String())
			}
			if rec.inFlight != 0 {
				t.Errorf("in-flight = %d after the request, want 0", rec.inFlight)
			}
		})
	}
}

func TestHandlerRecordsSourceEvents(t *testing.T) {
	modTime := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	rec := &recorder{}
	h := newTestHandler(fakeSource{res: &source.Result{Body: []byte(metrics), ModTime: modTime}}, 2, rec, &bytes.Buffer{}, false)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if fmt.Sprint(rec.reads) != fmt.Sprint([]int{len(metrics)}) {
		t.Errorf("reads = %v", rec.reads)
	}
	if fmt.Sprint(rec.parsed) != "[1]" {
		t.Errorf("parsed samples = %v, want [1]", rec.parsed)
	}
	if len(rec.modTimes) != 1 || !rec.modTimes[0].Equal(modTime) {
		t.Errorf("modTimes = %v", rec.modTimes)
	}
}

func TestHandlerConcurrencyLimit(t *testing.T) {
	src := &blockingSource{started: make(chan struct{}), release: make(chan struct{})}
	rec := &recorder{}
	var logs bytes.Buffer
	h := newTestHandler(src, 2, rec, &logs, false)

	// Fill both slots.
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			codes[i] = w.Code
		}()
		<-src.started
	}

	// The third request is refused at once, without reaching the source.
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		close(done)
	}()
	select {
	case <-done:
	case <-src.started:
		t.Fatal("third request reached the source")
	case <-time.After(2 * time.Second):
		t.Fatal("third request was queued instead of rejected")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("third request code = %d, want 503", w.Code)
	}

	// 404 and 405 do not need a slot.
	w404 := httptest.NewRecorder()
	h.ServeHTTP(w404, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w404.Code != http.StatusNotFound {
		t.Errorf("unknown path while full: code = %d, want 404", w404.Code)
	}

	close(src.release)
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("request %d code = %d, want 200", i, c)
		}
	}
	if rec.rejected != 1 || rec.maxIn != 2 || rec.inFlight != 0 {
		t.Errorf("rejected=%d maxInFlight=%d inFlight=%d, want 1 2 0", rec.rejected, rec.maxIn, rec.inFlight)
	}
	if !strings.Contains(logs.String(), "max_concurrent_requests reached") {
		t.Errorf("rejection not logged: %q", logs.String())
	}

	// Slots are released: a new request succeeds.
	src.release = make(chan struct{})
	close(src.release)
	go func() { <-src.started }()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Errorf("request after release: code = %d, want 200", w.Code)
	}
}

func TestHandlerClientCanceled(t *testing.T) {
	src := &blockingSource{started: make(chan struct{}, 1), release: make(chan struct{})}
	rec := &recorder{}
	h := newTestHandler(src, 2, rec, &bytes.Buffer{}, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx))

	if w.Code != http.StatusBadGateway {
		t.Errorf("code on the wire = %d, want 502 (never an empty 200)", w.Code)
	}
	if len(rec.failed) != 0 {
		t.Errorf("client cancellation counted as source failure: %v", rec.failed)
	}
	if want := []string{"/metrics 499"}; !slices.Equal(rec.served, want) {
		t.Errorf("served = %v, want %v (not a 5xx)", rec.served, want)
	}
}

func TestHandlerAccessLog(t *testing.T) {
	for _, access := range []bool{false, true} {
		t.Run(fmt.Sprintf("access=%v", access), func(t *testing.T) {
			var logs bytes.Buffer
			h := newTestHandler(fakeSource{res: &source.Result{Body: []byte(metrics)}}, 2, &recorder{}, &logs, access)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))

			logged := strings.Contains(logs.String(), "msg=request")
			if logged != access {
				t.Errorf("access line logged = %v, want %v (logs: %q)", logged, access, logs.String())
			}
			if access {
				for _, want := range []string{"listener=test", "route=/metrics", "code=200", "duration_ms=", "remote="} {
					if !strings.Contains(logs.String(), want) {
						t.Errorf("access line lacks %q: %q", want, logs.String())
					}
				}
			}
		})
	}
}

func TestNewHandlerFromConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.prom")
	if err := os.WriteFile(p, []byte(metrics), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(config.Listener{
		Name:                  "files",
		MaxConcurrentRequests: 2,
		Routes: []config.Route{{
			Path:   "/batch/metrics",
			File:   p,
			MaxAge: time.Hour,
			Limits: config.Limits{Timeout: time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 10},
		}},
	}, Options{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/batch/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("code = %d, want 200", resp.StatusCode)
	}
}

func TestScrapeBudget(t *testing.T) {
	tests := []struct {
		value  string
		want   time.Duration
		wantOK bool
	}{
		{"", 0, false},
		{"10", 9500 * time.Millisecond, true},
		{"14.5", 14 * time.Second, true},
		{"1", time.Second, true},     // too short for the margin: whole timeout
		{"0.3", time.Second, true},   // raised to minScrapeBudget
		{"1e-9", time.Second, true},  // cannot make healthy sources time out
		{"1.001", time.Second, true}, // margin taken, floor kept
		{"1.2", time.Second, true},
		{"2", 1500 * time.Millisecond, true},
		{"0", 0, false},
		{"-5", 0, false},
		{"abc", 0, false},
		{"NaN", 0, false},
		{"+Inf", 0, false},
		{"1e300", 86400*time.Second - scrapeMargin, true}, // capped, no overflow
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			h := http.Header{}
			if tt.value != "" {
				h.Set(scrapeTimeoutHeader, tt.value)
			}
			got, ok := scrapeBudget(h)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("scrapeBudget(%q) = %v, %v; want %v, %v", tt.value, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// deadlineSource records the deadline of the context it is given.
type deadlineSource struct {
	deadline time.Time
	has      bool
}

func (d *deadlineSource) Fetch(ctx context.Context) (*source.Result, error) {
	d.deadline, d.has = ctx.Deadline()
	return &source.Result{Body: []byte(metrics)}, nil
}

func TestHandlerPassesScrapeBudgetToSource(t *testing.T) {
	src := &deadlineSource{}
	h := newTestHandler(src, 2, &recorder{}, &bytes.Buffer{}, false)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if src.has {
		t.Error("deadline set without the scrape timeout header")
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(scrapeTimeoutHeader, "5")
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !src.has {
		t.Fatal("no deadline with the scrape timeout header")
	}
	if left := src.deadline.Sub(start); left > 4600*time.Millisecond || left < 4400*time.Millisecond {
		t.Errorf("deadline in %v, want about 4.5s (5s minus margin)", left)
	}
}

// With a real HTTP source slower than the scraper's timeout, the proxy
// answers 502 "timeout" before the scraper gives up, although the route
// timeout is longer.
func TestHandlerAnswersBeforeScraperTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()

	src, err := source.New(config.Route{
		Path:     "/metrics",
		Upstream: slow.URL + "/metrics",
		Limits:   config.Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	var logs bytes.Buffer
	h := newTestHandler(src, 2, rec, &logs, false)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(scrapeTimeoutHeader, "1")
	w := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "timeout") {
		t.Errorf("code %d body %q, want 502 timeout", w.Code, w.Body.String())
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("answered after %v, want within the 1s scrape timeout", elapsed)
	}
	if fmt.Sprint(rec.failed) != "[timeout]" {
		t.Errorf("failed reasons = %v, want [timeout]", rec.failed)
	}
	if !strings.Contains(logs.String(), "scrape_budget_ms=1000") {
		t.Errorf("budget not logged: %s", logs.String())
	}
}

// closingSource counts CloseIdleConnections calls.
type closingSource struct {
	fakeSource
	closed int
}

func (c *closingSource) CloseIdleConnections() { c.closed++ }

func TestHandlerCloseIdleConnections(t *testing.T) {
	src := &closingSource{}
	h := newHandler("node", []route{
		{path: "/a", src: src, maxSamples: 10},
		{path: "/b", src: fakeSource{}, maxSamples: 10}, // without the method
	}, 1, Options{})
	h.CloseIdleConnections()
	if src.closed != 1 {
		t.Errorf("CloseIdleConnections called %d times, want 1", src.closed)
	}
}

// Source failures a client can trigger at will are not all logged at warn.
func TestHandlerWarnLogsAreRateLimited(t *testing.T) {
	var logs bytes.Buffer
	rec := &recorder{}
	h := newTestHandler(fakeSource{err: source.NewError(source.ReasonUnavailable, "down")}, 2, rec, &logs, false)
	const n = logBurst + 20
	for range n {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	}
	if len(rec.failed) != n {
		t.Errorf("counted %d failures, want %d (all)", len(rec.failed), n)
	}
	warns := strings.Count(logs.String(), "level=WARN")
	if warns < logBurst || warns > logBurst+2 {
		t.Errorf("%d warn lines for %d failures, want about %d", warns, n, logBurst)
	}
}
