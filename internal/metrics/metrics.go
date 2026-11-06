// Package metrics exposes exporter_proxy's own metrics in the Prometheus
// format. It implements proxy.Recorder.
//
// Label values come from the configuration only (listener names, route
// paths, a fixed set of failure reasons and HTTP status codes), never from
// clients, to keep cardinality bounded.
package metrics

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

const namespace = "exporter_proxy"

// Path is where the metrics endpoint serves.
const Path = "/metrics"

// reasons lists every failure reason, to initialize their series at 0.
var reasons = []source.Reason{
	source.ReasonUnavailable, source.ReasonTimeout, source.ReasonTooLarge,
	source.ReasonStale, source.ReasonInvalid, source.ReasonTooManySamples,
}

// Metrics holds the registry and the collectors.
type Metrics struct {
	registry *prometheus.Registry

	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	parseDuration   *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
	samples         *prometheus.HistogramVec
	sourceErrors    *prometheus.CounterVec
	inFlight        *inFlightGauge
	rejected        *prometheus.CounterVec
	authFailures    *prometheus.CounterVec
	fileModified    *prometheus.GaugeVec

	configHash          prometheus.Gauge
	reloadSuccessful    prometheus.Gauge
	reloadSuccessTstamp prometheus.Gauge

	// mu protects routes. Recording methods hold it for reading, so that
	// ConfigLoaded never deletes series while they are being updated.
	mu sync.RWMutex
	// routes holds the listener and route paths of the loaded
	// configuration: series of removed ones are deleted on reload, and
	// events about them (requests still draining) are not recorded, so
	// that deleted series do not come back.
	routes map[string]map[string]bool
}

// New creates the metrics, registered in a dedicated registry together with
// the Go runtime, process and build_info collectors.
func New() *Metrics {
	lr := []string{"listener", "route"}
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "requests_total",
			Help: "Requests served, by listener, route (empty when no route matched) and HTTP status code.",
		}, []string{"listener", "route", "code"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "request_duration_seconds",
			Help:    "Time to serve a request: source read, validation and response.",
			Buckets: prometheus.DefBuckets,
		}, lr),
		parseDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "parse_duration_seconds",
			Help:    "Time spent validating content with the Prometheus text parser.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 12), // 0.5 ms to ~1 s
		}, lr),
		responseSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "response_size_bytes",
			Help:    "Size of the content read from the source.",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 8), // 1 KiB to 16 MiB
		}, lr),
		samples: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "samples",
			Help:    "Number of samples in the content read from the source.",
			Buckets: prometheus.ExponentialBuckets(10, 4, 8), // 10 to ~160k
		}, lr),
		sourceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "source_errors_total",
			Help: "Rejected scrapes by reason: unavailable, timeout, too_large, stale, invalid, too_many_samples.",
		}, []string{"listener", "route", "reason"}),
		inFlight: newInFlightGauge(prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "requests_in_flight"),
			"Requests currently reading a source.",
			[]string{"listener"}, nil)),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "requests_rejected_total",
			Help: "Requests refused with 503 because max_concurrent_requests was reached.",
		}, []string{"listener"}),
		authFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "auth_failures_total",
			Help: "Connections or requests refused before routing, by reason: tls_handshake, missing_credentials, invalid_credentials, rate_limited.",
		}, []string{"listener", "reason"}),
		fileModified: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "file_modified_timestamp_seconds",
			Help: "Modification time of the file of a file route, updated on every scrape.",
		}, lr),
		configHash: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "config_hash",
			Help: "First 48 bits of the SHA-256 of the loaded configuration file.",
		}),
		reloadSuccessful: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "config_last_reload_successful",
			Help: "Whether the last configuration load succeeded.",
		}),
		reloadSuccessTstamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "config_last_reload_success_timestamp_seconds",
			Help: "Time of the last successful configuration load.",
		}),
	}

	m.registry.MustRegister(
		m.requests, m.requestDuration, m.parseDuration, m.responseSize, m.samples,
		m.sourceErrors, m.inFlight, m.rejected, m.authFailures, m.fileModified,
		m.configHash, m.reloadSuccessful, m.reloadSuccessTstamp,
		versioncollector.NewCollector(namespace),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// ConfigLoaded records a successful configuration load (startup or reload).
// Series of listeners and routes that are no longer configured are deleted.
// Not safe for concurrent calls: loads are serialized by the caller.
func (m *Metrics) ConfigLoaded(cfg *config.Config, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configHash.Set(float64(cfg.Hash))
	m.reloadSuccessful.Set(1)
	m.reloadSuccessTstamp.Set(float64(at.Unix()))

	next := make(map[string]map[string]bool, len(cfg.Listeners))
	for _, l := range cfg.Listeners {
		next[l.Name] = make(map[string]bool, len(l.Routes))
		for _, r := range l.Routes {
			next[l.Name][r.Path] = true
		}
	}
	for listener, routes := range m.routes {
		if _, ok := next[listener]; !ok {
			m.deleteSeries(prometheus.Labels{"listener": listener})
			continue
		}
		for route := range routes {
			if !next[listener][route] {
				m.deleteSeries(prometheus.Labels{"listener": listener, "route": route})
			}
		}
	}
	m.routes = next
	m.inFlight.setListeners(next)

	// Initialize the series of every configured listener and route, so that
	// rates and alerts work from the first scrape.
	for _, reason := range proxy.AuthReasons {
		m.authFailures.WithLabelValues(config.MetricsListenerName, string(reason))
	}
	for _, l := range cfg.Listeners {
		m.rejected.WithLabelValues(l.Name)
		for _, reason := range proxy.AuthReasons {
			m.authFailures.WithLabelValues(l.Name, string(reason))
		}
		for _, r := range l.Routes {
			for _, reason := range reasons {
				m.sourceErrors.WithLabelValues(l.Name, r.Path, string(reason))
			}
		}
	}
}

// deleteSeries deletes the series matching labels in every vector that has
// all these labels.
func (m *Metrics) deleteSeries(labels prometheus.Labels) {
	routeVecs := []interface {
		DeletePartialMatch(prometheus.Labels) int
	}{m.requests, m.requestDuration, m.parseDuration, m.responseSize, m.samples, m.sourceErrors, m.fileModified}
	for _, v := range routeVecs {
		v.DeletePartialMatch(labels)
	}
	if _, ok := labels["route"]; !ok {
		m.rejected.DeletePartialMatch(labels)
		m.authFailures.DeletePartialMatch(labels)
	}
}

// ConfigLoadFailed records a failed configuration load (reload).
func (m *Metrics) ConfigLoadFailed() {
	m.reloadSuccessful.Set(0)
}

// Handler serves the registry on Path; other paths get 404.
func (m *Metrics) Handler(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(Path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		ErrorLog:            slog.NewLogLogger(logger.Handler(), slog.LevelError),
		Registry:            m.registry, // promhttp_metric_handler_errors_total
		MaxRequestsInFlight: 2,
		Timeout:             10 * time.Second,
	}))
	return mux
}

// Registry returns the registry, for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// proxy.Recorder implementation.

// known reports whether listener, and route unless empty, are in the
// loaded configuration. The metrics endpoint is always known. Called with
// m.mu held for reading.
func (m *Metrics) known(listener, route string) bool {
	if listener == config.MetricsListenerName && route == "" {
		return true
	}
	routes, ok := m.routes[listener]
	return ok && (route == "" || routes[route])
}

// RequestServed implements proxy.Recorder.
func (m *Metrics) RequestServed(listener, route string, code int, d time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, route) {
		return
	}
	m.requests.WithLabelValues(listener, route, strconv.Itoa(code)).Inc()
	if route != "" {
		m.requestDuration.WithLabelValues(listener, route).Observe(d.Seconds())
	}
}

// InFlight implements proxy.Recorder.
// Unlike the other events, it is counted for removed listeners too, so that
// the count stays right if a listener is added back while requests are
// still draining; only configured listeners are exported.
func (m *Metrics) InFlight(listener string, delta int) {
	m.inFlight.add(listener, delta)
}

// RequestRejected implements proxy.Recorder.
func (m *Metrics) RequestRejected(listener string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, "") {
		return
	}
	m.rejected.WithLabelValues(listener).Inc()
}

// SourceRead implements proxy.Recorder.
func (m *Metrics) SourceRead(listener, route string, size int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, route) {
		return
	}
	m.responseSize.WithLabelValues(listener, route).Observe(float64(size))
}

// FileModified implements proxy.Recorder.
func (m *Metrics) FileModified(listener, route string, t time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, route) {
		return
	}
	m.fileModified.WithLabelValues(listener, route).Set(float64(t.UnixNano()) / 1e9)
}

// ContentParsed implements proxy.Recorder.
func (m *Metrics) ContentParsed(listener, route string, samples int, d time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, route) {
		return
	}
	m.parseDuration.WithLabelValues(listener, route).Observe(d.Seconds())
	m.samples.WithLabelValues(listener, route).Observe(float64(samples))
}

// AuthFailed implements proxy.Recorder.
func (m *Metrics) AuthFailed(listener string, reason proxy.AuthReason) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, "") {
		return
	}
	m.authFailures.WithLabelValues(listener, string(reason)).Inc()
}

// SourceFailed implements proxy.Recorder.
func (m *Metrics) SourceFailed(listener, route string, reason source.Reason) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.known(listener, route) {
		return
	}
	m.sourceErrors.WithLabelValues(listener, route, string(reason)).Inc()
}

// inFlightGauge counts in-flight requests by listener. The counts are kept
// for every listener name, configured or not (requests of a removed
// listener may still be draining), and only configured listeners are
// exported.
type inFlightGauge struct {
	desc *prometheus.Desc

	mu       sync.Mutex
	counts   map[string]int
	exported map[string]map[string]bool // listener names (values unused)
}

func newInFlightGauge(desc *prometheus.Desc) *inFlightGauge {
	return &inFlightGauge{desc: desc, counts: map[string]int{}}
}

func (g *inFlightGauge) add(listener string, delta int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.counts[listener] += delta
	g.prune(listener)
}

// setListeners sets the exported listeners.
func (g *inFlightGauge) setListeners(listeners map[string]map[string]bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.exported = listeners
	for name := range g.counts {
		g.prune(name)
	}
}

// prune forgets an idle listener that is not exported. Called with g.mu held.
func (g *inFlightGauge) prune(listener string) {
	if _, ok := g.exported[listener]; !ok && g.counts[listener] == 0 {
		delete(g.counts, listener)
	}
}

// value returns the count of a listener, for tests.
func (g *inFlightGauge) value(listener string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counts[listener]
}

// Describe implements prometheus.Collector.
func (g *inFlightGauge) Describe(ch chan<- *prometheus.Desc) { ch <- g.desc }

// Collect implements prometheus.Collector.
func (g *inFlightGauge) Collect(ch chan<- prometheus.Metric) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for name := range g.exported {
		ch <- prometheus.MustNewConstMetric(g.desc, prometheus.GaugeValue, float64(g.counts[name]), name)
	}
}
