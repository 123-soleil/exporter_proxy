package proxy

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"strings"
	"sync"
)

// gzipMinSize is the smallest body worth compressing: below, the gzip
// header and the CPU cost outweigh the gain.
const gzipMinSize = 1024

// gzipWriters reuses compressors: allocating one costs about 800 KiB.
var gzipWriters = sync.Pool{
	New: func() any {
		// BestSpeed: metrics text compresses about tenfold even at the
		// fastest level, and a scrape must not wait on compression.
		w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
		return w
	},
}

// gzipBytes returns body compressed with gzip.
func gzipBytes(body []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(body) / 4)
	zw := gzipWriters.Get().(*gzip.Writer)
	defer gzipWriters.Put(zw)
	zw.Reset(&buf)
	// Writes to a bytes.Buffer cannot fail.
	_, _ = zw.Write(body)
	_ = zw.Close()
	return buf.Bytes()
}

// acceptsGzip reports whether an Accept-Encoding header value accepts gzip
// (RFC 9110, section 12.5.3): "gzip" or "*" with a quality above 0, an
// explicit "gzip;q=0" refusing it even when "*" is accepted.
func acceptsGzip(header string) bool {
	star := false
	for part := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(part, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "gzip" && name != "x-gzip" && name != "*" {
			continue
		}
		accepted := quality(params) > 0
		if name == "*" {
			star = accepted
			continue
		}
		return accepted
	}
	return star
}

// quality returns the q parameter of an Accept-Encoding entry, 1 when
// absent and 0 when malformed.
func quality(params string) float64 {
	for p := range strings.SplitSeq(params, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || q < 0 || q > 1 {
			return 0
		}
		return q
	}
	return 1
}
