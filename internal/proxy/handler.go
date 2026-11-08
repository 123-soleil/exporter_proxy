// Package proxy serves the routes of one listener: it reads the route's
// source, validates the content and returns it unchanged.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/time/rate"

	"github.com/prometheus/common/expfmt"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/content"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// contentType is the media type of the validated text exposition format.
const contentType = "text/plain; version=0.0.4; charset=utf-8"

// servedFormats are the formats the proxy validates, for negotiation.
var servedFormats = []expfmt.Format{expfmt.NewFormat(expfmt.TypeProtoDelim), expfmt.NewFormat(expfmt.TypeTextPlain)}

// protobufContentType is the media type of the delimited protobuf format.
const protobufContentType = "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited"

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
	// CacheHit is called for a request answered from the cache of a
	// route with cache_ttl.
	CacheHit(listener, route string)
	// RequestShared is called for a request answered with the result of a
	// read started by a concurrent request of the same route.
	RequestShared(listener, route string)
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
	AuthNetworkNotAllowed  AuthReason = "network_not_allowed" // client address outside allowed_networks
	AuthForbidden          AuthReason = "forbidden"           // authenticated, but not in the route's authorize
	AuthCertificateRevoked AuthReason = "certificate_revoked" // client certificate in the client_crl_file
)

// AuthReasons lists every AuthReason, to initialize metric series.
var AuthReasons = []AuthReason{AuthTLSHandshake, AuthMissingCredentials, AuthInvalidCredentials, AuthRateLimited,
	AuthNetworkNotAllowed, AuthForbidden, AuthCertificateRevoked}

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
	authz      *authorization                 // nil: every authenticated client
	params     map[string]config.ForwardParam // nil: the query string is ignored
	cacheTTL   time.Duration                  // 0: no cache
}

// Handler serves the routes of one listener.
type Handler struct {
	listener  string
	routes    map[string]route
	slots     chan struct{}
	logger    *slog.Logger
	rec       Recorder
	accessLog bool
	// mu protects reads, the source reads running, and cache, the results
	// kept for routes with cache_ttl, by route and format.
	mu    sync.Mutex
	reads map[string]*sharedRead
	cache map[string]*sharedRead
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
		routes = append(routes, route{path: r.Path, src: src, maxSamples: r.Limits.MaxSamples,
			authz: newAuthorization(r.Authorize), params: r.ForwardParams, cacheTTL: r.CacheTTL})
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
		reads:     map[string]*sharedRead{},
		cache:     map[string]*sharedRead{},
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
			// Client-supplied text (method, path) is cleaned like the
			// identities below.
			attrs := []any{"route", routeLabel, "method", logSafe(req.Method, 16),
				"path", logSafe(req.URL.Path, 256), "code", rw.status(), "size", rw.size,
				"duration_ms", d.Milliseconds(), "remote", req.RemoteAddr}
			// Verified identities only: they cannot be forged by the
			// client.
			if user, ok := userOf(req.Context()); ok {
				attrs = append(attrs, "user", logSafe(user, 64))
			}
			if name := certName(req.TLS); name != "" {
				attrs = append(attrs, "client_cert", logSafe(name, 64))
			}
			h.logger.Info("request", attrs...)
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

	if rt.authz != nil {
		if ok, who := rt.authz.allows(req); !ok {
			h.rec.AuthFailed(h.listener, AuthForbidden)
			h.logger.Log(req.Context(), h.warnLevel(), "request forbidden: not in the authorize list of the route",
				"route", rt.path, "user", truncate(who, 64), "remote", req.RemoteAddr)
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	query, problem := checkParams(rt.params, req.URL.RawQuery)
	if problem != "" {
		h.logger.Log(req.Context(), h.warnLevel(), "request refused: query string", "route", rt.path, "problem", problem)
		http.Error(rw, problem, http.StatusBadRequest)
		return
	}

	// Answer before the scraper gives up: its timeout can only shorten the
	// route timeout, which the source still applies.
	budget, hasBudget := scrapeBudget(req.Header)

	// The delimited protobuf format (native histograms) when the scraper
	// prefers it; files and upstreams without it answer in text.
	wantProto := expfmt.NegotiateAccept(req.Header, servedFormats...).FormatType() == expfmt.TypeProtoDelim
	rd, err := h.read(req.Context(), rt, source.Request{Protobuf: wantProto, Query: query}, budget, hasBudget)
	if errors.Is(err, errNoSlot) {
		h.rec.RequestRejected(h.listener)
		h.logger.Log(req.Context(), h.warnLevel(), "request rejected, max_concurrent_requests reached",
			"route", rt.path, "max_concurrent_requests", cap(h.slots))
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if req.Context().Err() != nil {
		// The client went away: not a source failure. Recorded as 499,
		// but a 502 is still written: a client that only half-closed its
		// connection may still read, and must not get an empty 200.
		h.logger.Debug("client canceled the request", "route", rt.path, "err", err)
		rw.code = statusClientClosedRequest
		rw.ResponseWriter.WriteHeader(http.StatusBadGateway)
		return
	}
	if err != nil {
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

	body := rd.body
	hdr := rw.Header()
	if rt.cacheTTL > 0 {
		// The answer may come from the cache: tell its age.
		hdr.Set("Age", strconv.Itoa(int(time.Since(rd.at).Seconds())))
	}
	hdr.Set("Content-Type", contentType)
	if rd.protobuf {
		hdr.Set("Content-Type", protobufContentType)
	}
	// The response depends on these request headers: caches must key on
	// them.
	hdr.Set("Vary", "Accept, Accept-Encoding")
	if len(body) >= gzipMinSize && acceptsGzip(req.Header.Get("Accept-Encoding")) {
		body = rd.gzipped()
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

// logSafe prepares text for logs: line breaks and other control
// characters removed (the log handlers escape them too), then cut to n
// bytes.
func logSafe(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return truncate(s, n)
}

// truncate cuts s to at most n bytes, for logs.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Never cut a UTF-8 character in two.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// scrapeTimeoutHeader is sent by Prometheus and vmagent with the scrape
// timeout of the target, in seconds.
const scrapeTimeoutHeader = source.ScrapeTimeoutHeader

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

// errNoSlot is returned by read when max_concurrent_requests is reached.
var errNoSlot = errors.New("max_concurrent_requests reached")

// sharedRead is one read of a route's source, whose result every request
// for that route arriving meanwhile gets.
type sharedRead struct {
	done     chan struct{} // closed once body, protobuf and err are set
	body     []byte
	protobuf bool // body is in the delimited protobuf format
	err      error

	gzipOnce sync.Once
	gzip     []byte

	at time.Time // when the read ended; set before done is closed

	// Protected by Handler.mu.
	clients int                // requests waiting for the result
	cancel  context.CancelFunc // cancels the read
}

// gzipped returns the body compressed, computed once for all the requests
// sharing the read.
func (r *sharedRead) gzipped() []byte {
	r.gzipOnce.Do(func() { r.gzip = gzipBytes(r.body) })
	return r.gzip
}

// read returns the validated content of rt. A request arriving while a
// read of the same route is running gets its result instead of reading
// again (two scrapers in high availability, for example): only that first
// read takes a concurrency slot. The read runs on its own, as long as one
// request waits for it: it is canceled once none does, and every request
// stops waiting when its client leaves or its scrape budget is spent.
func (h *Handler) read(ctx context.Context, rt route, sreq source.Request, budget time.Duration, hasBudget bool) (*sharedRead, error) {
	// Requests asking for different formats do not share reads.
	key := rt.path
	if sreq.Protobuf {
		key += "\x00protobuf"
	}
	// Nor requests forwarding different parameters (other targets).
	if len(sreq.Query) > 0 {
		key += "\x00?" + sreq.Query.Encode()
	}
	h.mu.Lock()
	if rt.cacheTTL > 0 {
		if c := h.cache[key]; c != nil && time.Since(c.at) < rt.cacheTTL {
			h.mu.Unlock()
			h.rec.CacheHit(h.listener, rt.path)
			return c, nil
		}
	}
	rd, ok := h.reads[key]
	if ok {
		rd.clients++
		h.mu.Unlock()
		h.rec.RequestShared(h.listener, rt.path)
	} else {
		// Never queue: a full listener answers immediately.
		select {
		case h.slots <- struct{}{}:
		default:
			h.mu.Unlock()
			return nil, errNoSlot
		}
		fetchCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		rd = &sharedRead{done: make(chan struct{}), clients: 1, cancel: cancel}
		h.reads[key] = rd
		h.mu.Unlock()
		h.rec.InFlight(h.listener, 1)
		// No scrape budget on the read itself, only the route timeout
		// (applied by the source): the request starting it must not cut it
		// short for those joining it with a longer budget. Each request
		// waits at most its own budget, and the read is canceled once none
		// waits.
		go func() {
			defer cancel()
			rd.body, rd.protobuf, rd.err = h.safeFetch(fetchCtx, rt, sreq)
			rd.at = time.Now()
			h.mu.Lock()
			if h.reads[key] == rd {
				delete(h.reads, key)
			}
			// Only validated results are kept: a failure is retried by
			// the next request.
			if rt.cacheTTL > 0 && rd.err == nil {
				h.cache[key] = rd
			}
			h.mu.Unlock()
			// The slot is free before anyone gets the result: a scraper's
			// next request finds it available.
			<-h.slots
			h.rec.InFlight(h.listener, -1)
			close(rd.done)
		}()
	}

	wait := ctx
	if hasBudget {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	select {
	case <-rd.done:
		return rd, rd.err
	case <-wait.Done():
	}
	select {
	case <-rd.done: // finished at the same time: use it
		return rd, rd.err
	default:
	}
	h.leave(key, rd)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, source.NewError(source.ReasonTimeout,
		"no complete answer within %s (left by the scraper's timeout)", budget.Round(time.Millisecond))
}

// safeFetch is fetch for a read running on its own goroutine, where a
// panic (a bug in a source or a parser fed by an upstream) would stop the
// whole process instead of failing one request: it becomes a source
// error.
func (h *Handler) safeFetch(ctx context.Context, rt route, req source.Request) (body []byte, protobuf bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			h.logger.Error("panic while reading the source", "route", rt.path, "panic", fmt.Sprint(p),
				"stack", string(debug.Stack()))
			body, protobuf, err = nil, false, source.NewError(source.ReasonUnavailable, "internal error while reading the source")
		}
	}()
	return h.fetch(ctx, rt, req)
}

// leave records that a request no longer waits for rd: the last one
// leaving cancels the read, and later requests start a new one.
func (h *Handler) leave(key string, rd *sharedRead) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rd.clients--
	if rd.clients > 0 {
		return
	}
	if h.reads[key] == rd {
		delete(h.reads, key)
	}
	rd.cancel()
}

// fetch reads the source and validates its content.
func (h *Handler) fetch(ctx context.Context, rt route, req source.Request) (body []byte, protobuf bool, err error) {
	res, err := rt.src.Fetch(ctx, req)
	if res != nil && !res.ModTime.IsZero() {
		h.rec.FileModified(h.listener, rt.path, res.ModTime)
	}
	if err != nil {
		return nil, false, err
	}
	h.rec.SourceRead(h.listener, rt.path, len(res.Body))

	parsed, err := content.ValidateFormat(res.Body, rt.maxSamples, res.Protobuf)
	h.rec.ContentParsed(h.listener, rt.path, parsed.Samples, parsed.Duration, err == nil)
	if err != nil {
		return nil, false, err
	}
	return res.Body, res.Protobuf, nil
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
func (NopRecorder) RequestShared(string, string)                           {}
func (NopRecorder) CacheHit(string, string)                                {}
func (NopRecorder) WebConfigRead(string, bool, bool)                       {}
