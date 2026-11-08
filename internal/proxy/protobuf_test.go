package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// formatSource answers in protobuf when asked, and records the requests.
type formatSource struct {
	mu   sync.Mutex
	reqs []source.Request
	pb   []byte
}

func (f *formatSource) Fetch(_ context.Context, req source.Request) (*source.Result, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if req.Protobuf {
		return &source.Result{Body: f.pb, Protobuf: true}, nil
	}
	return &source.Result{Body: []byte(metrics)}, nil
}

// prometheusProtoAccept is the Accept header of Prometheus with native
// histograms enabled.
const prometheusProtoAccept = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.6," +
	"application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,text/plain;version=0.0.4;q=0.2,*/*;q=0.1"

func TestHandlerNegotiatesProtobuf(t *testing.T) {
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeProtoDelim))
	if err := enc.Encode(&dto.MetricFamily{Name: proto.String("up"), Type: dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(1)}}}}); err != nil {
		t.Fatal(err)
	}
	src := &formatSource{pb: buf.Bytes()}
	h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100}}, 2, Options{})

	tests := []struct {
		name, accept, wantType string
		wantProtoReq           bool
		wantBody               []byte
	}{
		{"prometheus with native histograms", prometheusProtoAccept, protobufContentType, true, buf.Bytes()},
		{"text scraper", "text/plain;version=0.0.4", contentType, false, []byte(metrics)},
		{"no Accept", "", contentType, false, []byte(metrics)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src.mu.Lock()
			src.reqs = nil
			src.mu.Unlock()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("code %d: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if got := w.Header().Get("Vary"); got != "Accept, Accept-Encoding" {
				t.Errorf("Vary = %q", got)
			}
			if !bytes.Equal(w.Body.Bytes(), tt.wantBody) {
				t.Error("body differs from the source content")
			}
			src.mu.Lock()
			defer src.mu.Unlock()
			if len(src.reqs) != 1 || src.reqs[0].Protobuf != tt.wantProtoReq {
				t.Errorf("source requests = %+v, want Protobuf %v", src.reqs, tt.wantProtoReq)
			}
		})
	}
}

// An invalid protobuf body is rejected like invalid text.
func TestHandlerRejectsInvalidProtobuf(t *testing.T) {
	src := &formatSource{pb: []byte("\x05garbage")}
	h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100}}, 2, Options{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", prometheusProtoAccept)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway || w.Body.String() != "source rejected: invalid\n" {
		t.Errorf("code %d body %q, want 502 invalid", w.Code, w.Body.String())
	}
}

// A malicious upstream announcing a huge protobuf message gets the scrape
// rejected, and the process keeps running.
func TestHandlerSurvivesHugeProtobufPrefix(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", protobufContentType)
		_, _ = w.Write(protowire.AppendVarint(nil, 1<<62))
	}))
	defer up.Close()
	src, err := source.New(config.Route{Path: "/metrics", Upstream: up.URL,
		Limits: config.Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1 << 20, MaxSamples: 100}})
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 100}}, 2, Options{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", prometheusProtoAccept)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway || w.Body.String() != "source rejected: invalid\n" {
		t.Errorf("code %d body %q, want 502 invalid", w.Code, w.Body.String())
	}
}
