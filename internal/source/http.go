package source

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/common/version"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// acceptHeader requests the Prometheus text exposition format, the only
// format the proxy validates and serves.
const acceptHeader = "text/plain;version=0.0.4;q=1,*/*;q=0.1"

// httpSource fetches an HTTP exporter over TCP or over a Unix socket.
type httpSource struct {
	url          string
	timeout      time.Duration
	maxBodyBytes int64
	client       *http.Client
}

func newHTTPSource(r config.Route) (*httpSource, error) {
	dialer := &net.Dialer{Timeout: r.Limits.Timeout, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		// Never use HTTP_PROXY/HTTPS_PROXY: scrapes must go straight to the
		// configured upstream.
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		// Compression stays enabled: the transport decompresses gzip
		// transparently and readLimited bounds the decompressed size.
	}
	if r.UnixSocket != "" {
		socket := r.UnixSocket
		// The URL host is ignored: every connection goes to the socket,
		// like curl --unix-socket.
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		}
	}

	client := &http.Client{
		Transport: transport,
		// Redirects are not followed: a 3xx is a failure like any non-200.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &httpSource{
		url:          r.Upstream,
		timeout:      r.Limits.Timeout,
		maxBodyBytes: r.Limits.MaxBodyBytes,
		client:       client,
	}, nil
}

// CloseIdleConnections closes the idle connections to the upstream.
func (s *httpSource) CloseIdleConnections() { s.client.CloseIdleConnections() }

func (s *httpSource) Fetch(parent context.Context) (*Result, error) {
	limit := timeLimit(parent, time.Now(), s.timeout)
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, &Error{Reason: ReasonUnavailable, Err: err}
	}
	// Only these headers are sent: nothing from the client request
	// (Authorization in particular) is forwarded.
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("User-Agent", version.ComponentUserAgent("exporter_proxy"))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, classify(ctx, err, limit)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, newError(ReasonUnavailable, "upstream returned HTTP %d", resp.StatusCode)
	}
	// Reject early when the announced size is already too large. Not valid
	// for compressed bodies, whose decompressed size is checked while reading.
	if !resp.Uncompressed && resp.ContentLength > s.maxBodyBytes {
		return nil, newError(ReasonTooLarge, "content length %d exceeds max_body_bytes (%d)",
			resp.ContentLength, s.maxBodyBytes)
	}

	body, err := readLimited(resp.Body, s.maxBodyBytes)
	if err != nil {
		return nil, classify(ctx, fmt.Errorf("read upstream body: %w", err), limit)
	}
	return &Result{Body: body}, nil
}
