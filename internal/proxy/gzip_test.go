package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/123-soleil/exporter_proxy/internal/source"
)

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"GZIP", true},
		{"x-gzip", true},
		{"identity", false},
		{"br, gzip;q=0.5", true},
		{"gzip;q=0", false},
		{"gzip; q=0.0", false},
		{"*", true},
		{"*;q=0", false},
		{"*, gzip;q=0", false},
		{"gzip;q=0, *", false},
		{"deflate, br", false},
		{"gzip;q=abc", false},
		{"gzip;q=2", false},
	}
	for _, tt := range tests {
		if got := acceptsGzip(tt.header); got != tt.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}

// bigMetrics returns valid metrics text of at least gzipMinSize bytes.
func bigMetrics() string {
	var b strings.Builder
	b.WriteString("# TYPE n gauge\n")
	for i := 0; b.Len() < 4*gzipMinSize; i++ {
		fmt.Fprintf(&b, "n{instance=\"host-%d\",job=\"node\"} %d\n", i%90, i)
	}
	return b.String()
}

func TestHandlerCompressesWithGzip(t *testing.T) {
	big := bigMetrics()
	tests := []struct {
		name           string
		method         string
		body           string
		acceptEncoding string
		wantGzip       bool
	}{
		{"accepted", http.MethodGet, big, "gzip, deflate", true},
		{"not accepted", http.MethodGet, big, "", false},
		{"refused", http.MethodGet, big, "gzip;q=0", false},
		{"too small to be worth it", http.MethodGet, metrics, "gzip", false},
		{"head", http.MethodHead, big, "gzip", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := fakeSource{res: &source.Result{Body: []byte(tt.body)}}
			h := newHandler("test", []route{{path: "/metrics", src: src, maxSamples: 1 << 20}}, 2, Options{})
			req := httptest.NewRequest(tt.method, "/metrics", nil)
			if tt.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tt.acceptEncoding)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("code %d", w.Code)
			}
			if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Errorf("Vary = %q, want Accept-Encoding", got)
			}
			gzipped := w.Header().Get("Content-Encoding") == "gzip"
			if gzipped != tt.wantGzip {
				t.Fatalf("Content-Encoding = %q, want gzip: %v", w.Header().Get("Content-Encoding"), tt.wantGzip)
			}
			length, _ := strconv.Atoi(w.Header().Get("Content-Length"))
			if tt.method == http.MethodHead {
				if w.Body.Len() != 0 || length == 0 || length >= len(tt.body) {
					t.Errorf("HEAD: body %d bytes, Content-Length %d (want the compressed size)", w.Body.Len(), length)
				}
				return
			}
			if length != w.Body.Len() {
				t.Errorf("Content-Length %d, body %d bytes", length, w.Body.Len())
			}
			got := w.Body.Bytes()
			if gzipped {
				if len(got) >= len(tt.body)/2 {
					t.Errorf("compressed to %d bytes from %d: not compressed", len(got), len(tt.body))
				}
				zr, err := gzip.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Fatal(err)
				}
				if got, err = io.ReadAll(zr); err != nil {
					t.Fatal(err)
				}
			}
			if string(got) != tt.body {
				t.Error("body differs from the source content")
			}
		})
	}
}
