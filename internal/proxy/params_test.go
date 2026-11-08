package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

var probeParams = map[string]config.ForwardParam{
	"target": {
		Values:   []string{"https://www.example.com"},
		Patterns: []*regexp.Regexp{regexp.MustCompile(config.AnchorPattern(`10\.0\.0\.[0-9]{1,3}:443`))},
		Required: true,
	},
	"module": {Values: []string{"http_2xx", "tcp_connect"}},
}

func TestCheckParams(t *testing.T) {
	tests := []struct {
		query, problem string
	}{
		{"target=https://www.example.com", ""},
		{"target=10.0.0.7:443&module=tcp_connect", ""},
		{"target=10.0.0.7:443&debug=true", "query parameter not allowed"},
		{"target=169.254.169.254:80", `value not allowed for query parameter "target"`},
		{"target=10.0.0.7:443&target=https://www.example.com", `query parameter "target" given more than once`},
		{"module=http_2xx", `query parameter "target" is required`},
		{"target=%zz", "malformed query string"},
		{"target=" + strings.Repeat("a", config.MaxParamValueLength+1), `query parameter "target" too long`},
	}
	for _, tt := range tests {
		_, problem := checkParams(probeParams, tt.query)
		if problem != tt.problem {
			t.Errorf("%q: problem %q, want %q", tt.query, problem, tt.problem)
		}
	}
	// Without forward_params the query string is ignored.
	if q, problem := checkParams(nil, "anything=1"); q != nil || problem != "" {
		t.Errorf("without forward_params: %v %q", q, problem)
	}
}

// The upstream gets the allowed parameters with its own; requests for
// different targets never share a read.
func TestForwardParamsReachTheUpstream(t *testing.T) {
	var mu sync.Mutex
	var got []string
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.URL.RawQuery)
		mu.Unlock()
		<-release
		_, _ = fmt.Fprintf(w, "probe_success{target=%q} 1\n", r.URL.Query().Get("target"))
	}))
	defer up.Close()
	src, err := source.New(config.Route{Path: "/probe", Upstream: up.URL + "/probe?debug=false",
		Limits: config.Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 100}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler("test", []route{{path: "/probe", src: src, maxSamples: 100, params: probeParams}}, 4, Options{})

	results := make(chan string, 2)
	for _, target := range []string{"10.0.0.1:443", "10.0.0.2:443"} {
		go func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe?target="+target, nil))
			results <- w.Body.String()
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d upstream reads, want 2 (different targets must not share a read)", n)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	bodies := []string{<-results, <-results}
	for _, target := range []string{"10.0.0.1:443", "10.0.0.2:443"} {
		if !strings.Contains(bodies[0]+bodies[1], target) {
			t.Errorf("no answer for %s: %q", target, bodies)
		}
	}
	mu.Lock()
	for _, q := range got {
		if !strings.Contains(q, "debug=false") || !strings.Contains(q, "target=10.0.0.") {
			t.Errorf("upstream query %q: want the upstream URL's own parameters and the target", q)
		}
	}

	// A refused query never reaches the upstream.
	got = nil
	mu.Unlock()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe?target=127.0.0.1:22", nil).WithContext(context.Background()))
	mu.Lock()
	defer mu.Unlock()
	if w.Code != http.StatusBadRequest || len(got) != 0 {
		t.Errorf("refused target: code %d, upstream reads %d; want 400 and none", w.Code, len(got))
	}
}

// The upstream is told the scrape budget of the request, not the longer
// route timeout: blackbox_exporter then answers probe_success 0 before the
// scraper gives up, instead of the scrape failing as a whole.
func TestUpstreamToldTheScrapeBudget(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(source.ScrapeTimeoutHeader)
		_, _ = fmt.Fprint(w, metrics)
	}))
	defer up.Close()
	src, err := source.New(config.Route{Path: "/m", Upstream: up.URL,
		Limits: config.Limits{Timeout: 10 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 100}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler("test", []route{{path: "/m", src: src, maxSamples: 100}}, 2, Options{})
	req := httptest.NewRequest(http.MethodGet, "/m", nil)
	req.Header.Set(scrapeTimeoutHeader, "3")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "2.500" {
		t.Errorf("upstream told %q, want 2.500 (3s scrape timeout minus the margin)", got)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/m", nil))
	if secs, _ := strconv.ParseFloat(got, 64); secs < 9 || secs > 10 {
		t.Errorf("without a scrape timeout: upstream told %q, want the route timeout", got)
	}
}
