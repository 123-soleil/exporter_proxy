package source

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

const metrics = "# TYPE up gauge\nup 1\n"

func limits(timeout time.Duration, maxBody int64) config.Limits {
	return config.Limits{Timeout: timeout, MaxBodyBytes: maxBody, MaxSamples: 1000}
}

func mustNew(t *testing.T, r config.Route) Source {
	t.Helper()
	s, err := New(r)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// checkErr verifies that err has the wanted reason ("" means success).
func checkErr(t *testing.T, err error, want Reason) {
	t.Helper()
	if got := ReasonOf(err); got != want {
		t.Fatalf("reason = %q, want %q (err: %v)", got, want, err)
	}
	if err != nil && strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("error spans several lines: %q", err)
	}
}

func TestHTTPSource(t *testing.T) {
	big := strings.Repeat("x", 2000)

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		timeout  time.Duration
		maxBody  int64
		want     Reason
		wantBody string
	}{
		{
			name:     "ok",
			handler:  func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, metrics) },
			want:     "",
			wantBody: metrics,
		},
		{
			name:     "body exactly at the limit",
			handler:  func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, metrics) },
			maxBody:  int64(len(metrics)),
			want:     "",
			wantBody: metrics,
		},
		{
			name:    "HTTP error status",
			handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
			want:    ReasonUnavailable,
		},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
			},
			want: ReasonUnavailable,
		},
		{
			name: "slow upstream",
			handler: func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			},
			timeout: 50 * time.Millisecond,
			want:    ReasonTimeout,
		},
		{
			name: "slow body after headers",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, "# partial\n")
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
				}
			},
			timeout: 50 * time.Millisecond,
			want:    ReasonTimeout,
		},
		{
			name: "announced length too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "2000")
				_, _ = fmt.Fprint(w, big)
			},
			maxBody: 100,
			want:    ReasonTooLarge,
		},
		{
			name: "chunked body too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				for i := 0; i < 20; i++ {
					_, _ = fmt.Fprint(w, big[:100])
					w.(http.Flusher).Flush()
				}
			},
			maxBody: 100,
			want:    ReasonTooLarge,
		},
		{
			name: "gzip body checked on decompressed size",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
					t.Error("transport did not ask for gzip")
				}
				w.Header().Set("Content-Encoding", "gzip")
				gz := gzip.NewWriter(w)
				_, _ = fmt.Fprint(gz, big) // ~30 bytes compressed, 2000 decompressed
				_ = gz.Close()
			},
			maxBody: 100,
			want:    ReasonTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			timeout, maxBody := tt.timeout, tt.maxBody
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			if maxBody == 0 {
				maxBody = 1 << 20
			}
			s := mustNew(t, config.Route{Upstream: srv.URL + "/metrics", Limits: limits(timeout, maxBody)})

			res, err := s.Fetch(context.Background(), Request{})
			checkErr(t, err, tt.want)
			if tt.want == "" && string(res.Body) != tt.wantBody {
				t.Errorf("body = %q, want %q", res.Body, tt.wantBody)
			}
		})
	}
}

func TestHTTPSourceRequest(t *testing.T) {
	var got *http.Request
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		got = r.Clone(context.Background())
		_, _ = fmt.Fprint(w, metrics)
	}))
	defer srv.Close()

	// A proxy from the environment must be ignored.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	s := mustNew(t, config.Route{Upstream: srv.URL + "/metrics?collect=a", Limits: limits(2*time.Second, 1<<20)})
	ctx := context.Background()
	if _, err := s.Fetch(ctx, Request{}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if hits.Load() != 1 {
		t.Fatalf("upstream hit %d times, want 1", hits.Load())
	}
	if got.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.Method)
	}
	if got.URL.Path != "/metrics" || got.URL.RawQuery != "collect=a" {
		t.Errorf("URL = %s, want /metrics?collect=a", got.URL)
	}
	if a := got.Header.Get("Accept"); !strings.HasPrefix(a, "text/plain;version=0.0.4") {
		t.Errorf("Accept = %q, want text format first", a)
	}
	if ua := got.Header.Get("User-Agent"); !strings.HasPrefix(ua, "exporter_proxy/") {
		t.Errorf("User-Agent = %q", ua)
	}
	if got.Header.Get("Authorization") != "" {
		t.Error("Authorization header sent upstream")
	}
}

func TestHTTPSourceRedirectTargetNotHit(t *testing.T) {
	var targetHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		_, _ = fmt.Fprint(w, metrics)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := mustNew(t, config.Route{Upstream: srv.URL + "/metrics", Limits: limits(time.Second, 1<<20)})
	_, err := s.Fetch(context.Background(), Request{})
	checkErr(t, err, ReasonUnavailable)
	if targetHits.Load() != 0 {
		t.Error("redirect was followed")
	}
}

func TestHTTPSourceConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	s := mustNew(t, config.Route{Upstream: url + "/metrics", Limits: limits(time.Second, 1<<20)})
	_, err := s.Fetch(context.Background(), Request{})
	checkErr(t, err, ReasonUnavailable)
}

// shortTempDir returns a temporary directory with a short path: Unix socket
// paths are limited to about 108 bytes, too short for t.TempDir() names.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ep")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestUnixSocketSource(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotHost, gotPath string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		_, _ = fmt.Fprint(w, metrics)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	s := mustNew(t, config.Route{
		Upstream:   "http://localhost/app/metrics",
		UnixSocket: sock,
		Limits:     limits(2*time.Second, 1<<20),
	})
	res, err := s.Fetch(context.Background(), Request{})
	checkErr(t, err, "")
	if string(res.Body) != metrics {
		t.Errorf("body = %q", res.Body)
	}
	if gotHost != "localhost" || gotPath != "/app/metrics" {
		t.Errorf("request host/path = %q %q, want localhost /app/metrics", gotHost, gotPath)
	}

	missing := mustNew(t, config.Route{
		Upstream:   "http://localhost/metrics",
		UnixSocket: filepath.Join(filepath.Dir(sock), "missing.sock"),
		Limits:     limits(time.Second, 1<<20),
	})
	_, err = missing.Fetch(context.Background(), Request{})
	checkErr(t, err, ReasonUnavailable)
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		mtime := time.Now().Add(-age)
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}

	fresh := write("fresh.prom", metrics, time.Minute)
	stale := write("stale.prom", metrics, 2*time.Hour)
	big := write("big.prom", strings.Repeat("x", 2000), 0)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		path        string
		maxBody     int64
		want        Reason
		wantModTime bool
	}{
		{name: "ok", path: fresh, want: "", wantModTime: true},
		{name: "missing", path: filepath.Join(dir, "missing.prom"), want: ReasonUnavailable},
		{name: "directory", path: dir, want: ReasonUnavailable},
		{name: "fifo does not block", path: fifo, want: ReasonUnavailable},
		{name: "stale", path: stale, want: ReasonStale, wantModTime: true},
		{name: "too large", path: big, maxBody: 100, want: ReasonTooLarge, wantModTime: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxBody := tt.maxBody
			if maxBody == 0 {
				maxBody = 1 << 20
			}
			s := mustNew(t, config.Route{File: tt.path, MaxAge: time.Hour, Limits: limits(time.Second, maxBody)})

			done := make(chan struct{})
			var res *Result
			var err error
			go func() {
				defer close(done)
				res, err = s.Fetch(context.Background(), Request{})
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Fetch blocked")
			}

			checkErr(t, err, tt.want)
			if tt.want == "" && string(res.Body) != metrics {
				t.Errorf("body = %q", res.Body)
			}
			if tt.want != "" && res != nil && res.Body != nil {
				t.Error("body returned with an error")
			}
			if tt.wantModTime && (res == nil || res.ModTime.IsZero()) {
				t.Error("ModTime not returned")
			}
		})
	}
}

func TestFileSourceTimeout(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.prom")
	if err := os.WriteFile(p, []byte(metrics), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newFileSource(config.Route{File: p, MaxAge: time.Hour, Limits: limits(time.Second, 1<<20)})

	// Simulate a read that takes longer than the timeout.
	calls := 0
	base := time.Now()
	s.now = func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(5 * time.Second)
	}
	_, err := s.Fetch(context.Background(), Request{})
	checkErr(t, err, ReasonTimeout)
}

func TestReasonOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Reason
	}{
		{"nil", nil, ""},
		{"plain error", errors.New("x"), ReasonUnavailable},
		{"source error", newError(ReasonStale, "x"), ReasonStale},
		{"wrapped source error", fmt.Errorf("ctx: %w", newError(ReasonTooLarge, "x")), ReasonTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReasonOf(tt.err); got != tt.want {
				t.Errorf("ReasonOf = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTTPSourceCloseIdleConnections(t *testing.T) {
	src, err := New(config.Route{Upstream: "http://127.0.0.1:1/metrics", Limits: config.Limits{Timeout: time.Second, MaxBodyBytes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := src.(interface{ CloseIdleConnections() })
	if !ok {
		t.Fatal("HTTP source does not implement CloseIdleConnections")
	}
	c.CloseIdleConnections()
}

// A limit at the int64 maximum must not overflow into "read nothing".
func TestReadLimitedHugeLimit(t *testing.T) {
	body, err := readLimited(strings.NewReader("up 1\n"), math.MaxInt64)
	if err != nil || string(body) != "up 1\n" {
		t.Errorf("readLimited = %q, %v; want the whole body", body, err)
	}
}

// A file modified far in the future cannot be trusted as fresh.
func TestFileSourceFutureModTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.prom")
	if err := os.WriteFile(p, []byte("up 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	src, err := New(config.Route{File: p, MaxAge: time.Hour, Limits: config.Limits{Timeout: time.Second, MaxBodyBytes: 1 << 10}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Fetch(context.Background(), Request{})
	if ReasonOf(err) != ReasonStale || !strings.Contains(err.Error(), "in the future") {
		t.Errorf("err = %v, want stale, modified in the future", err)
	}

	// Within max_age in the future (small clock skew): accepted.
	soon := time.Now().Add(time.Minute)
	if err := os.Chtimes(p, soon, soon); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Fetch(context.Background(), Request{}); err != nil {
		t.Errorf("small skew rejected: %v", err)
	}
}

// The timeout message names the limit that fired.
func TestTimeLimit(t *testing.T) {
	start := time.Now()
	if got := timeLimit(context.Background(), start, 10*time.Second); got != "10s (route timeout)" {
		t.Errorf("without deadline: %q", got)
	}
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(4500*time.Millisecond))
	defer cancel()
	if got := timeLimit(ctx, start, 10*time.Second); got != "4.5s (left by the scraper's timeout, route timeout 10s)" {
		t.Errorf("with an earlier deadline: %q", got)
	}
}

// A protobuf request asks the upstream for protobuf first; the answer's
// format comes from its Content-Type.
func TestHTTPSourceProtobuf(t *testing.T) {
	const protoType = "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited"
	tests := []struct {
		name        string
		protobuf    bool
		contentType string
		wantAccept  string
		wantProto   bool
	}{
		{"text requested", false, protoType, "text/plain;version=0.0.4;q=1", false},
		{"protobuf answered", true, protoType, "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited", true},
		{"text answered", true, "text/plain; version=0.0.4", "application/vnd.google.protobuf", false},
		{"no content type", true, "", "application/vnd.google.protobuf", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var accept string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				accept = r.Header.Get("Accept")
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				_, _ = fmt.Fprint(w, metrics)
			}))
			defer srv.Close()
			s := mustNew(t, config.Route{Upstream: srv.URL + "/metrics", Limits: limits(2*time.Second, 1<<20)})
			res, err := s.Fetch(context.Background(), Request{Protobuf: tt.protobuf})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(accept, tt.wantAccept) {
				t.Errorf("Accept = %q, want prefix %q", accept, tt.wantAccept)
			}
			if res.Protobuf != tt.wantProto {
				t.Errorf("Protobuf = %v, want %v", res.Protobuf, tt.wantProto)
			}
		})
	}
}
