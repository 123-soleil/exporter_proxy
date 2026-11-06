// Package server runs one HTTP server per configured listener, with TLS,
// mTLS and basic authentication handled by prometheus/exporter-toolkit.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// HTTP server limits. Write deadlines are derived from the route timeouts.
const (
	readHeaderTimeout = 10 * time.Second // slow clients sending headers
	idleTimeout       = 60 * time.Second // keep-alive between scrapes
	maxHeaderBytes    = 16 << 10         // scrape requests are tiny
	writeMargin       = 10 * time.Second // parsing and sending after the source read

	// metricsWriteTimeout covers promhttp's own 10 s timeout.
	metricsWriteTimeout = 10*time.Second + writeMargin
)

// MetricsListener is the name of the metrics endpoint in logs and in
// Server.Addr. Configuration validation reserves it.
const MetricsListener = config.MetricsListenerName

// Options configures the servers.
type Options struct {
	Logger    *slog.Logger
	Recorder  proxy.Recorder
	AccessLog bool
	// MetricsHandler serves the metrics endpoint described by cfg.Metrics.
	// Nil: the metrics endpoint is not started.
	MetricsHandler http.Handler
}

// Server is the set of running listeners.
type Server struct {
	logger    *slog.Logger
	listeners []*listener
	errc      chan error
	wg        sync.WaitGroup
}

type listener struct {
	name string
	ln   net.Listener
	srv  *http.Server
}

// spec describes one server to start: a configured listener or the metrics
// endpoint.
type spec struct {
	name         string
	listen       string
	webConfig    string
	handler      http.Handler
	writeTimeout time.Duration
}

// Start validates the web configuration files, binds every listener address,
// then serves them all. Nothing is served unless every listener could be
// set up: on error, already bound addresses are released.
func Start(cfg *config.Config, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// 1. Handlers.
	var specs []spec
	if opts.MetricsHandler != nil {
		specs = append(specs, spec{
			name:         MetricsListener,
			listen:       cfg.Metrics.Listen,
			webConfig:    cfg.Metrics.WebConfigFile,
			handler:      opts.MetricsHandler,
			writeTimeout: metricsWriteTimeout,
		})
	}
	for _, l := range cfg.Listeners {
		h, err := proxy.NewHandler(l, proxy.Options{
			Logger:    logger,
			Recorder:  opts.Recorder,
			AccessLog: opts.AccessLog,
		})
		if err != nil {
			return nil, err
		}
		var maxTimeout time.Duration
		for _, r := range l.Routes {
			maxTimeout = max(maxTimeout, r.Limits.Timeout)
		}
		specs = append(specs, spec{
			name:         l.Name,
			listen:       l.Listen,
			webConfig:    l.WebConfigFile,
			handler:      h,
			writeTimeout: maxTimeout + writeMargin,
		})
	}

	// 2. Web configuration files: report every invalid one at once.
	var problems []string
	for _, sp := range specs {
		if err := web.Validate(sp.webConfig); err != nil {
			problems = append(problems, fmt.Sprintf("listener %q: web_config_file %s: %s",
				sp.name, sp.webConfig, oneLine(err)))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid web configuration: %s", strings.Join(problems, "; "))
	}
	for _, sp := range specs {
		if wc, err := webconfig.Read(sp.webConfig); err == nil && wc.BasicAuthWithoutTLS() {
			logger.Warn("basic authentication without TLS: credentials travel in clear text",
				"listener", sp.name, "web_config_file", sp.webConfig)
		}
	}

	// 3. Bind every address (or take every systemd socket) before serving
	// any, so that a port conflict fails the whole startup.
	sockets, err := takeSystemdSockets(specs, logger)
	if err != nil {
		return nil, err
	}
	s := &Server{logger: logger, errc: make(chan error, len(specs))}
	for _, sp := range specs {
		var ln net.Listener
		if name, ok := config.SystemdSocketName(sp.listen); ok {
			ln = sockets[name]
		} else if ln, err = net.Listen("tcp", sp.listen); err != nil {
			s.closeListeners()
			closeAll(sockets)
			return nil, fmt.Errorf("listener %q: %w", sp.name, err)
		}
		s.listeners = append(s.listeners, &listener{
			name: sp.name,
			ln:   ln,
			srv:  newHTTPServer(sp, logger),
		})
	}

	// 4. Serve.
	for i, l := range s.listeners {
		webConfig := specs[i].webConfig
		systemdSocket := false
		flags := &web.FlagConfig{
			WebListenAddresses: &[]string{},
			WebSystemdSocket:   &systemdSocket,
			WebConfigFile:      &webConfig,
		}
		llog := logger.With("listener", l.name)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := web.Serve(l.ln, l.srv, flags, llog)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.errc <- fmt.Errorf("listener %q: %w", l.name, err)
			}
		}()
	}
	return s, nil
}

func newHTTPServer(sp spec, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           sp.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readHeaderTimeout,
		WriteTimeout:      sp.writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// TLS handshake failures (wrong or missing client certificate)
		// are security relevant: log them.
		ErrorLog: slog.NewLogLogger(logger.With("listener", sp.name).Handler(), slog.LevelWarn),
	}
}

// Addr returns the bound address of a listener, or nil if unknown.
func (s *Server) Addr(name string) net.Addr {
	for _, l := range s.listeners {
		if l.name == name {
			return l.ln.Addr()
		}
	}
	return nil
}

// Err reports the first listener that stops serving unexpectedly.
func (s *Server) Err() <-chan error { return s.errc }

// Shutdown stops accepting connections and waits for in-flight requests to
// complete, until ctx is done; remaining connections are then closed.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, l := range s.listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.srv.Shutdown(ctx); err != nil {
				_ = l.srv.Close()
				mu.Lock()
				errs = append(errs, fmt.Errorf("listener %q: %w", l.name, err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	s.wg.Wait()
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	// One line, unlike errors.Join.
	return errors.New(strings.Join(msgs, "; "))
}

// systemdListeners returns the sockets passed by systemd socket activation,
// by FileDescriptorName=. Replaced in tests.
var systemdListeners = activation.ListenersWithNames

// takeSystemdSockets returns, by name, the socket of each listener whose
// listen value is "systemd:<name>". Each name must match exactly one
// stream socket; sockets passed by systemd but not configured are closed.
func takeSystemdSockets(specs []spec, logger *slog.Logger) (map[string]net.Listener, error) {
	wanted := map[string]string{} // socket name -> listener name
	for _, sp := range specs {
		if name, ok := config.SystemdSocketName(sp.listen); ok {
			wanted[name] = sp.name
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	passed, err := systemdListeners()
	if err != nil {
		return nil, fmt.Errorf("systemd socket activation: %w", err)
	}
	sockets := make(map[string]net.Listener, len(wanted))
	var problems []string
	for name, lns := range passed {
		var stream []net.Listener
		for _, ln := range lns {
			if ln != nil { // nil for non-stream sockets (datagram, FIFO)
				stream = append(stream, ln)
			}
		}
		listener, used := wanted[name]
		switch {
		case !used:
			logger.Warn("systemd socket not used by any listener, closing it", "socket", name)
			closeAll(nil, stream...)
		case len(stream) != 1:
			problems = append(problems, fmt.Sprintf("listener %q: systemd socket %q must be exactly one stream socket, got %d",
				listener, name, len(stream)))
			closeAll(nil, stream...)
		default:
			sockets[name] = stream[0]
		}
	}
	for name, listener := range wanted {
		if _, ok := passed[name]; !ok {
			problems = append(problems, fmt.Sprintf("listener %q: no systemd socket named %q (FileDescriptorName=)", listener, name))
		}
	}
	if len(problems) > 0 {
		closeAll(sockets)
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return sockets, nil
}

// closeAll closes the listeners of a map and the extra ones given.
func closeAll(m map[string]net.Listener, extra ...net.Listener) {
	for _, ln := range m {
		if ln != nil {
			_ = ln.Close()
		}
	}
	for _, ln := range extra {
		_ = ln.Close()
	}
}

func (s *Server) closeListeners() {
	for _, l := range s.listeners {
		_ = l.ln.Close()
	}
}

// oneLine keeps an error on a single log line.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
