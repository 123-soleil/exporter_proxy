// Package server runs one HTTP server per configured listener, with TLS,
// mTLS and basic authentication handled by prometheus/exporter-toolkit.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

	// drainTimeout bounds the graceful stop of a listener removed or
	// replaced by a reload.
	drainTimeout = 15 * time.Second
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
	logger *slog.Logger
	opts   Options
	errc   chan error

	mu        sync.Mutex
	listeners map[string]*listener // by name

	serving  sync.WaitGroup // web.Serve goroutines
	draining sync.WaitGroup // listeners stopped by a reload
}

type listener struct {
	tls     bool
	spec    spec
	ln      net.Listener
	srv     *http.Server
	handler *swapHandler
}

// spec describes one server: a configured listener or the metrics endpoint.
type spec struct {
	name         string
	listen       string
	webConfig    string
	handler      http.Handler
	writeTimeout time.Duration
}

// swapHandler serves through a handler that a reload can replace
// atomically, and applies the matching write deadline to each request.
type swapHandler struct {
	cur atomic.Pointer[handlerState]
}

type handlerState struct {
	h            http.Handler
	writeTimeout time.Duration
}

func newSwapHandler(sp spec) *swapHandler {
	sh := &swapHandler{}
	sh.store(sp)
	return sh
}

func (sh *swapHandler) store(sp spec) {
	sh.cur.Store(&handlerState{h: sp.handler, writeTimeout: sp.writeTimeout})
}

func (sh *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := sh.cur.Load()
	// Per-request deadline: route timeouts may change on reload without
	// restarting the server. Ignored if the writer does not support it.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(st.writeTimeout))
	st.h.ServeHTTP(w, r)
}

// Start validates the web configuration files, binds every listener address,
// then serves them all. Nothing is served unless every listener could be
// set up: on error, already bound addresses are released.
func Start(cfg *config.Config, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		logger:    opts.Logger,
		opts:      opts,
		errc:      make(chan error, 16),
		listeners: map[string]*listener{},
	}

	specs, err := s.prepare(cfg)
	if err != nil {
		return nil, err
	}

	// Bind every address (or take every systemd socket) before serving any,
	// so that a port conflict fails the whole startup.
	sockets, err := takeSystemdSockets(specs, s.logger)
	if err != nil {
		return nil, err
	}
	var bound []*listener
	for _, sp := range specs {
		var ln net.Listener
		if name, ok := config.SystemdSocketName(sp.listen); ok {
			ln = sockets[name]
		} else if ln, err = net.Listen("tcp", sp.listen); err != nil {
			closeListeners(bound)
			closeAll(sockets)
			return nil, fmt.Errorf("listener %q: %w", sp.name, err)
		}
		l, err := s.newListener(sp, ln)
		if err != nil {
			_ = ln.Close()
			closeListeners(bound)
			closeAll(sockets)
			return nil, err
		}
		bound = append(bound, l)
	}

	for _, l := range bound {
		s.listeners[l.spec.name] = l
		s.serve(l)
	}
	return s, nil
}

// Reload applies a new configuration. Either everything is applied or
// nothing is: on error the running listeners are left untouched.
//
//   - a listener with the same name, address and web configuration keeps
//     its socket and connections; its routes and limits are swapped;
//   - a listener whose address is already served (web configuration
//     changed, listener renamed) gets a duplicate of the socket, so the port
//     is never closed, and the previous server is stopped gracefully;
//   - a new address is bound; systemd sockets can only be taken at startup;
//   - a removed listener is stopped gracefully (in-flight requests complete,
//     up to 15 s).
func (s *Server) Reload(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	specs, err := s.prepare(cfg)
	if err != nil {
		return err
	}

	byListen := map[string]*listener{}
	for _, l := range s.listeners {
		byListen[l.spec.listen] = l
	}

	type swap struct {
		l  *listener
		sp spec
	}
	var swaps []swap
	var started []*listener
	kept := map[string]bool{}
	for _, sp := range specs {
		cur := s.listeners[sp.name]
		if cur != nil && cur.spec.listen == sp.listen && cur.spec.webConfig == sp.webConfig {
			swaps = append(swaps, swap{cur, sp})
			kept[sp.name] = true
			continue
		}

		var ln net.Listener
		var err error
		_, systemd := config.SystemdSocketName(sp.listen)
		switch old := byListen[sp.listen]; {
		case old != nil:
			ln, err = dupListener(old.ln)
		case systemd:
			err = errors.New("systemd sockets are only taken at startup: restart the service to use a new one")
		default:
			ln, err = net.Listen("tcp", sp.listen)
		}
		if err != nil {
			closeListeners(started)
			return fmt.Errorf("listener %q: %w", sp.name, err)
		}
		l, err := s.newListener(sp, ln)
		if err != nil {
			_ = ln.Close()
			closeListeners(started)
			return err
		}
		started = append(started, l)
	}

	// Commit: nothing below can fail.
	for _, sw := range swaps {
		sw.l.spec = sw.sp
		sw.l.handler.store(sw.sp)
	}
	next := make(map[string]*listener, len(specs))
	for name := range kept {
		next[name] = s.listeners[name]
	}
	for _, l := range started {
		next[l.spec.name] = l
		s.serve(l)
		s.logger.Info("listener started", "listener", l.spec.name, "address", l.ln.Addr().String())
	}
	for name, l := range s.listeners {
		if !kept[name] {
			s.logger.Info("listener stopping", "listener", name, "address", l.ln.Addr().String())
			s.drain(l)
		}
	}
	s.listeners = next
	return nil
}

// prepare builds the handlers of cfg and validates the web configuration
// files, reporting every invalid one at once.
func (s *Server) prepare(cfg *config.Config) ([]spec, error) {
	var specs []spec
	if s.opts.MetricsHandler != nil {
		specs = append(specs, spec{
			name:         MetricsListener,
			listen:       cfg.Metrics.Listen,
			webConfig:    cfg.Metrics.WebConfigFile,
			handler:      s.opts.MetricsHandler,
			writeTimeout: metricsWriteTimeout,
		})
	}
	for _, l := range cfg.Listeners {
		h, err := proxy.NewHandler(l, proxy.Options{
			Logger:    s.logger,
			Recorder:  s.opts.Recorder,
			AccessLog: s.opts.AccessLog,
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
			s.logger.Warn("basic authentication without TLS: credentials travel in clear text",
				"listener", sp.name, "web_config_file", sp.webConfig)
		}
	}
	return specs, nil
}

// newListener prepares the HTTP server of sp on ln: TLS settings and the
// authentication layer come from its web configuration file. It does not
// serve yet.
func (s *Server) newListener(sp spec, ln net.Listener) (*listener, error) {
	wc, err := webconfig.Load(sp.webConfig)
	if err != nil {
		return nil, fmt.Errorf("listener %q: %w", sp.name, err)
	}

	sh := newSwapHandler(sp)
	auth := newAuthHandler(sp.name, sp.webConfig,
		webRateLimit{interval: wc.RateLimiterConfig.Interval, burst: wc.RateLimiterConfig.Burst},
		sh, s.logger, s.recorder())
	srv := &http.Server{
		Handler:           auth,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readHeaderTimeout,
		// Baseline until the handler sets the per-request deadline.
		WriteTimeout:   writeMargin,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
		// TLS handshake failures are counted and logged as such.
		ErrorLog: log.New(&serverErrorLog{listener: sp.name, logger: s.logger, rec: s.recorder()}, "", 0),
	}

	l := &listener{spec: sp, ln: ln, srv: srv, handler: sh}
	if !wc.TLSConfig.IsEnabled() {
		return l, nil
	}

	tlsCfg, err := web.ConfigToTLSConfig(&wc.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("listener %q: web_config_file %s: %w", sp.name, sp.webConfig, err)
	}
	nextProtos := []string{"http/1.1"}
	if wc.HTTPConfig.HTTP2 {
		nextProtos = []string{"h2", "http/1.1"}
	} else {
		// A non-nil empty map disables HTTP/2 in net/http.
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	tlsCfg.NextProtos = nextProtos
	// Certificates, key and client CA are re-read on every new connection,
	// like exporter-toolkit: renewed files apply without restart.
	webConfig, logger := sp.webConfig, s.logger.With("listener", sp.name)
	tlsCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c, err := webconfig.Load(webConfig)
		if err == nil {
			var cfg *tls.Config
			if cfg, err = web.ConfigToTLSConfig(&c.TLSConfig); err == nil {
				cfg.NextProtos = nextProtos
				return cfg, nil
			}
		}
		logger.Error("cannot load TLS settings for a new connection", "web_config_file", webConfig, "err", oneLine(err))
		return nil, err
	}
	srv.TLSConfig = tlsCfg
	l.tls = true
	return l, nil
}

func (s *Server) recorder() proxy.Recorder {
	if s.opts.Recorder == nil {
		return proxy.NopRecorder{}
	}
	return s.opts.Recorder
}

// serve serves l in the background.
func (s *Server) serve(l *listener) {
	s.logger.Info("listening", "listener", l.spec.name, "address", l.ln.Addr().String(), "tls", l.tls)
	s.serving.Add(1)
	go func() {
		defer s.serving.Done()
		var err error
		if l.tls {
			err = l.srv.ServeTLS(l.ln, "", "")
		} else {
			err = l.srv.Serve(l.ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case s.errc <- fmt.Errorf("listener %q: %w", l.spec.name, err):
			default: // an error is already pending
			}
		}
	}()
}

// drain stops l gracefully in the background.
func (s *Server) drain(l *listener) {
	s.draining.Add(1)
	go func() {
		defer s.draining.Done()
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := l.srv.Shutdown(ctx); err != nil {
			_ = l.srv.Close()
			s.logger.Warn("listener stopped with requests still running", "listener", l.spec.name, "err", err)
		}
	}()
}

// dupListener returns a new listener on the same socket as ln, so that
// ln can be closed without closing the port.
func dupListener(ln net.Listener) (net.Listener, error) {
	fl, ok := ln.(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("cannot duplicate a %T", ln)
	}
	f, err := fl.File()
	if err != nil {
		return nil, fmt.Errorf("duplicate socket: %w", err)
	}
	defer func() { _ = f.Close() }()
	dup, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("duplicate socket: %w", err)
	}
	return dup, nil
}

// Addr returns the bound address of a listener, or nil if unknown.
func (s *Server) Addr(name string) net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.listeners[name]; ok {
		return l.ln.Addr()
	}
	return nil
}

// Err reports the first listener that stops serving unexpectedly.
func (s *Server) Err() <-chan error { return s.errc }

// Shutdown stops accepting connections and waits for in-flight requests to
// complete, until ctx is done; remaining connections are then closed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	listeners := make([]*listener, 0, len(s.listeners))
	for _, l := range s.listeners {
		listeners = append(listeners, l)
	}
	s.mu.Unlock()

	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.srv.Shutdown(ctx); err != nil {
				_ = l.srv.Close()
				mu.Lock()
				errs = append(errs, fmt.Sprintf("listener %q: %v", l.spec.name, err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	s.draining.Wait()
	s.serving.Wait()
	if len(errs) == 0 {
		return nil
	}
	// One line, unlike errors.Join.
	return errors.New(strings.Join(errs, "; "))
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

func closeListeners(ls []*listener) {
	for _, l := range ls {
		_ = l.ln.Close()
	}
}

// oneLine keeps an error on a single log line.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
