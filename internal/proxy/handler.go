// Package proxy serves the routes of one listener: it reads the route's
// source, validates the content and returns it unchanged.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

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
	// ContentParsed is called after parsing, successful or not.
	ContentParsed(listener, route string, samples int, duration time.Duration)
	// SourceFailed is called for every rejected scrape.
	SourceFailed(listener, route string, reason source.Reason)
}

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
	}
	if h.logger == nil {
		h.logger = slog.New(slog.DiscardHandler)
	}
	if h.rec == nil {
		h.rec = nopRecorder{}
	}
	h.logger = h.logger.With("listener", listener)
	for _, r := range routes {
		h.routes[r.path] = r
	}
	return h
}

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
		h.logger.Warn("request rejected, max_concurrent_requests reached",
			"route", rt.path, "max_concurrent_requests", cap(h.slots))
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	h.rec.InFlight(h.listener, 1)
	defer func() {
		<-h.slots
		h.rec.InFlight(h.listener, -1)
	}()

	body, err := h.fetch(req.Context(), rt)
	if err != nil {
		if req.Context().Err() != nil {
			// The client went away: not a source failure, nobody to answer.
			h.logger.Debug("client canceled the request", "route", rt.path, "err", err)
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		reason := source.ReasonOf(err)
		h.rec.SourceFailed(h.listener, rt.path, reason)
		h.logger.Warn("source rejected", "route", rt.path, "reason", string(reason),
			"duration_ms", time.Since(start).Milliseconds(), "err", err)
		// The client only gets the reason; details (paths, addresses) stay
		// in the logs.
		http.Error(rw, "source rejected: "+string(reason), http.StatusBadGateway)
		return
	}

	hdr := rw.Header()
	hdr.Set("Content-Type", contentType)
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
	h.rec.ContentParsed(h.listener, rt.path, parsed.Samples, parsed.Duration)
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

type nopRecorder struct{}

func (nopRecorder) RequestServed(string, string, int, time.Duration) {}
func (nopRecorder) InFlight(string, int)                             {}
func (nopRecorder) RequestRejected(string)                           {}
func (nopRecorder) SourceRead(string, string, int)                   {}
func (nopRecorder) FileModified(string, string, time.Time)           {}
func (nopRecorder) ContentParsed(string, string, int, time.Duration) {}
func (nopRecorder) SourceFailed(string, string, source.Reason)       {}
