package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/version"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// ScrapeTimeoutHeader carries a scrape timeout in seconds: sent by
// Prometheus to the proxy, and by the proxy to HTTP upstreams.
const ScrapeTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"

// acceptHeader requests the Prometheus text exposition format.
const acceptHeader = "text/plain;version=0.0.4;q=1,*/*;q=0.1"

// acceptProtobuf requests the delimited protobuf format first (native
// histograms), the text format as fallback. Both are validated.
const acceptProtobuf = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;escaping=allow-utf-8;q=1," +
	"text/plain;version=0.0.4;q=0.5,*/*;q=0.1"

// maxResponseHeaderBytes bounds the headers of an upstream answer.
const maxResponseHeaderBytes = 64 << 10

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
		Proxy:       nil,
		DialContext: dialer.DialContext,
		// An exporter's answer has a few headers: without a bound, one
		// sending megabytes of them made each read allocate far more than
		// max_body_bytes.
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		// Compression stays enabled: the transport decompresses gzip
		// transparently and readLimited bounds the decompressed size.
	}
	if strings.HasPrefix(r.Upstream, "https://") {
		tlsCfg, err := upstreamTLSConfig(r.UpstreamTLS)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
		transport.TLSHandshakeTimeout = r.Limits.Timeout
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

// upstreamTLSConfig builds the TLS settings of an https:// upstream. Its
// files are read now: at startup and on every reload, which fails if they
// cannot be used. The upstream certificate is always verified.
func upstreamTLSConfig(t *config.UpstreamTLS) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if t == nil {
		return cfg, nil // system roots, server name from the URL
	}
	cfg.ServerName = t.ServerName
	if t.CAFile != "" {
		data, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_tls ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("upstream_tls ca_file %s: no certificate found", t.CAFile)
		}
		cfg.RootCAs = pool
	}
	if t.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_tls cert_file and key_file: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// CloseIdleConnections closes the idle connections to the upstream.
func (s *httpSource) CloseIdleConnections() { s.client.CloseIdleConnections() }

func (s *httpSource) Fetch(parent context.Context, r Request) (*Result, error) {
	limit := timeLimit(parent, time.Now(), s.timeout)
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()

	target := s.url
	if len(r.Query) > 0 {
		// Appended to the upstream URL's query as written, which is never
		// rewritten (validation ensures the names differ).
		sep := "?"
		if strings.Contains(s.url, "?") {
			sep = "&"
		}
		target = s.url + sep + r.Query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, &Error{Reason: ReasonUnavailable, Err: withoutURL(err)}
	}
	// Only these headers are sent: nothing from the client request
	// (Authorization in particular) is forwarded.
	accept := acceptHeader
	if r.Protobuf {
		accept = acceptProtobuf
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", version.ComponentUserAgent("exporter_proxy"))
	// The time this read may take, computed here (never copied from the
	// client): exporters such as blackbox_exporter or snmp_exporter bound
	// their work with it.
	if d, ok := ctx.Deadline(); ok {
		if left := time.Until(d); left > 0 {
			if r.Timeout > 0 && r.Timeout < left {
				left = r.Timeout
			}
			req.Header.Set(ScrapeTimeoutHeader, strconv.FormatFloat(left.Seconds(), 'f', 3, 64))
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, classify(ctx, withoutURL(err), limit)
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
	// Anything but delimited protobuf is validated as text.
	proto := r.Protobuf && expfmt.ResponseFormat(resp.Header).FormatType() == expfmt.TypeProtoDelim
	return &Result{Body: body, Protobuf: proto}, nil
}

// withoutURL drops the URL that net/http quotes in its errors ("Get
// \"http://...\": ..."): logged on every failed scrape, it would copy its
// path and query (tokens, or credentials mistaken for a path by a URL like
// http://user:1234/secret@host) into the logs. The route identifies the
// source; the method and cause are kept.
func withoutURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("%s upstream: %w", uerr.Op, uerr.Err)
	}
	return err
}
