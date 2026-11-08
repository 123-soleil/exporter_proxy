// Package proxy serves the routes of one listener: it reads the route's
// source, validates the content and returns it unchanged.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/content"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// contentType is the media type of the validated text exposition format.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// Recorder receives the events used for the proxy's own metrics. Route
// labels are configured paths only; unmatched requests use route "".
type Recorder interface {
	// RequestServed is called once per request with its final status code.
	RequestServed(listener, route string, code int, duration time.Duration)
	// InFlight is called with +1 when a request takes a concurrency slot
	// and -1 when it releases it.
	InFlight(listener string, delta int)
	// RequestRejected is called when max_concurrent_requests is reached.
	RequestRejected(listener string)
	// SourceRead is called after a successful source read.
	SourceRead(listener, route string, size int)
	// FileModified reports the modification time of a file source.
	FileModified(listener, route string, modTime time.Time)
	// ContentParsed is called after parsing, successful or not; samples is
	// only meaningful when valid.
	ContentParsed(listener, route string, samples int, duration time.Duration, valid bool)
	// SourceFailed is called for every rejected scrape.
	SourceFailed(listener, route string, reason source.Reason)
	// AuthFailed is called for every request or connection refused before
	// routing (TLS handshake, basic authentication, rate limiting).
	AuthFailed(listener string, reason AuthReason)
	// WebConfigRead is called after each read of the web configuration
	// file of a listener, with whether it could be read and applied: on
	// every request (tls false), and on every new TLS connection, which also
	// loads the certificate, key and client CA (tls true).
	WebConfigRead(listener string, tls, ok bool)
}

// AuthReason classifies a refused authentication. Values are metric label
// values: keep the set small and fixed.
type AuthReason string

// Authentication failure reasons.
const (
	AuthTLSHandshake       AuthReason = "tls_handshake"       // TLS or mTLS handshake failed
	AuthMissingCredentials AuthReason = "missing_credentials" // basic auth required, none sent
	AuthInvalidCredentials AuthReason = "invalid_credentials" // unknown user or wrong password
	AuthRateLimited        AuthReason = "rate_limited"        // too many attempts, answered 429
)

// AuthReasons lists every AuthReason, to initialize metric series.
var AuthReasons = []AuthReason{AuthTLSHandshake, AuthMissingCredentials, AuthInvalidCredentials, AuthRateLimited}

// Options configures a handler.
type Options struct {
	Logger    *slog.Logger
	Recorder  Recorder // nil: no metrics
	AccessLog bool     // log one info line per request
}

type route struct {
	path       string
	src        source.Source
	maxSamples int
}

// Handler serves the routes of one listener.
type Handler struct {
	listener  string
	routes    map[string]route
	slots     chan struct{}
	logger    *slog.Logger
	rec       Recorder
	accessLog bool
	// logs bounds the warn lines a client can trigger on this listener
	// (rejections, source failures): beyond, they are logged at debug
	// level. They are all counted in the metrics.
	logs *rate.Limiter
}

// Rate of the warn lines of a listener, like its authentication refusals.
const (
	logRate  = 1 // per second
	logBurst = 10
)

// warnLevel returns slog.LevelWarn within the log rate, debug beyond.
func (h *Handler) warnLevel() slog.Level {
	if h.logs.Allow() {
		return slog.LevelWarn
	}
	return slog.LevelDebug
}

// NewHandler builds the handler of a validated listener configuration.
func NewHandler(l config.Listener, opts Options) (*Handler, error) {
	routes := make([]route, 0, len(l.Routes))
	for _, r := range l.Routes {
		src, err := source.New(r)
		if err != nil {
			return nil, fmt.Errorf("listener %q route %q: %w", l.Name, r.Path, err)
		}
		routes = append(routes, route{path: r.Path, src: src, maxSamples: r.Limits.MaxSamples})
	}
	return newHandler(l.Name, routes, l.MaxConcurrentRequests, opts), nil
}

func newHandler(listener string, routes []route, maxConcurrent int, opts Options) *Handler {
	h := &Handler{
		listener:  listener,
		routes:    make(map[string]route, len(routes)),
		slots:     make(chan struct{}, maxConcurrent),
		logger:    opts.Logger,
		rec:       opts.Recorder,
		accessLog: opts.AccessLog,
		logs:      rate.NewLimiter(logRate, logBurst),
	}
	if h.logger == nil {
		h.logger = slog.New(slog.DiscardHandler)
	}
	if h.rec == nil {
		h.rec = NopRecorder{}
	}
	h.logger = h.logger.With("listener", listener)
	for _, r := range routes {
		h.routes[r.path] = r
	}
	return h
}

// CloseIdleConnections closes the idle upstream connections of every route,
// for a handler replaced by a reload or stopped.
func (h *Handler) CloseIdleConnections() {
	for _, r := range h.routes {
		if c, ok := r.src.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

// statusClientClosedRequest is recorded when the client goes away before
// the answer (nginx convention), so that it is not counted as a 5xx.
const statusClientClosedRequest = 499

// ServeHTTP checks the route and method, takes a concurrency slot, then
// reads, validates and returns the source content.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	rw := &statusWriter{ResponseWriter: w}

	rt, ok := h.routes[req.URL.Path]
	routeLabel := ""
	if ok {
		routeLabel = rt.path
	}
	defer func() {
		d := time.Since(start)
		h.rec.RequestServed(h.listener, routeLabel, rw.status(), d)
		if h.accessLog {
			h.logger.Info("request", "route", routeLabel, "method", req.Method,
				"path", req.URL.Path, "code", rw.status(), "size", rw.size,
				"duration_ms", d.Milliseconds(), "remote", req.RemoteAddr)
		}
	}()

	switch {
	case !ok:
		http.NotFound(rw, req)
		return
	case req.Method != http.MethodGet && req.Method != http.MethodHead:
		rw.Header().Set("Allow", "GET, HEAD")
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// Never queue: a full listener answers immediately.
	select {
	case h.slots <- struct{}{}:
	default:
		h.rec.RequestRejected(h.listener)
		h.logger.Log(req.Context(), h.warnLevel(), "request rejected, max_concurrent_requests reached",
			"route", rt.path, "max_concurrent_requests", cap(h.slots))
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	h.rec.InFlight(h.listener, 1)
	defer func() {
		<-h.slots
		h.rec.InFlight(h.listener, -1)
	}()

	// Answer before the scraper gives up: its timeout can only shorten the
	// route timeout, which the source still applies.
	ctx := req.Context()
	budget, hasBudget := scrapeBudget(req.Header)
	if hasBudget {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	body, err := h.fetch(ctx, rt)
	if err != nil {
		if req.Context().Err() != nil {
			// The client went away: not a source failure. Recorded as 499,
			// but a 502 is still written: a client that only half-closed
			// its connection may still read, and must not get an empty 200.
			h.logger.Debug("client canceled the request", "route", rt.path, "err", err)
			rw.code = statusClientClosedRequest
			rw.ResponseWriter.WriteHeader(http.StatusBadGateway)
			return
		}
		reason := source.ReasonOf(err)
		h.rec.SourceFailed(h.listener, rt.path, reason)
		attrs := []any{"route", rt.path, "reason", string(reason),
			"duration_ms", time.Since(start).Milliseconds(), "err", err}
		if hasBudget {
			attrs = append(attrs, "scrape_budget_ms", budget.Milliseconds())
		}
		h.logger.Log(req.Context(), h.warnLevel(), "source rejected", attrs...)
		// The client only gets the reason; details (paths, addresses) stay
		// in the logs.
		http.Error(rw, "source rejected: "+string(reason), http.StatusBadGateway)
		return
	}

	hdr := rw.Header()
	hdr.Set("Content-Type", contentType)
	// The response depends on Accept-Encoding: caches must key on it.
	hdr.Set("Vary", "Accept-Encoding")
	if len(body) >= gzipMinSize && acceptsGzip(req.Header.Get("Accept-Encoding")) {
		body = gzipBytes(body)
		hdr.Set("Content-Encoding", "gzip")
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(http.StatusOK)
	if req.Method == http.MethodHead {
		return
	}
	if _, err := rw.Write(body); err != nil {
		h.logger.Debug("writing response failed", "route", rt.path, "err", err)
	}
}

// scrapeTimeoutHeader is sent by Prometheus and vmagent with the scrape
// timeout of the target, in seconds.
const scrapeTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"

// scrapeMargin is kept from the scraper's timeout to validate the content
// and send the answer.
const scrapeMargin = 500 * time.Millisecond

// minScrapeBudget is the least time the scraper's timeout header leaves to
// the source, so that a client cannot make healthy sources fail with
// "timeout" (counted and alerted on as source failures) by announcing a
// tiny timeout. Real scrape timeouts are at least a second.
const minScrapeBudget = time.Second

// scrapeBudget returns the time available to read the source according to
// the scraper's timeout header: the timeout minus scrapeMargin, or the whole
// timeout when it is too short for the margin, and never less than
// minScrapeBudget (so the budget never decreases when the timeout grows).
// ok is false when the header is missing or invalid.
func scrapeBudget(h http.Header) (time.Duration, bool) {
	v := h.Get(scrapeTimeoutHeader)
	if v == "" {
		return 0, false
	}
	secs, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(secs) || math.IsInf(secs, 0) || secs <= 0 {
		return 0, false
	}
	// Cap absurd values before converting (a day is far above any route
	// timeout, which bounds the read anyway).
	timeout := time.Duration(math.Min(secs, 86400) * float64(time.Second))
	budget := timeout
	if timeout > 2*scrapeMargin {
		budget = timeout - scrapeMargin
	}
	return max(budget, minScrapeBudget), true
}

// fetch reads the source and validates its content.
func (h *Handler) fetch(ctx context.Context, rt route) ([]byte, error) {
	res, err := rt.src.Fetch(ctx)
	if res != nil && !res.ModTime.IsZero() {
		h.rec.FileModified(h.listener, rt.path, res.ModTime)
	}
	if err != nil {
		return nil, err
	}
	h.rec.SourceRead(h.listener, rt.path, len(res.Body))

	parsed, err := content.Validate(res.Body, rt.maxSamples)
	h.rec.ContentParsed(h.listener, rt.path, parsed.Samples, parsed.Duration, err == nil)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

// statusWriter records the status code and body size of a response.
type statusWriter struct {
	http.ResponseWriter
	code int
	size int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// NopRecorder is a Recorder that records nothing.
type NopRecorder struct{}

func (NopRecorder) RequestServed(string, string, int, time.Duration)       {}
func (NopRecorder) InFlight(string, int)                                   {}
func (NopRecorder) RequestRejected(string)                                 {}
func (NopRecorder) SourceRead(string, string, int)                         {}
func (NopRecorder) FileModified(string, string, time.Time)                 {}
func (NopRecorder) ContentParsed(string, string, int, time.Duration, bool) {}
func (NopRecorder) AuthFailed(string, AuthReason)                          {}
func (NopRecorder) SourceFailed(string, string, source.Reason)             {}
func (NopRecorder) WebConfigRead(string, bool, bool)                       {}
