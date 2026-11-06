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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v3"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
)

// HTTP server limits. Write deadlines are derived from the route timeouts.
const (
	readHeaderTimeout = 10 * time.Second // slow clients sending headers
	idleTimeout       = 60 * time.Second // keep-alive between scrapes
	maxHeaderBytes    = 16 << 10         // scrape requests are tiny
	writeMargin       = 10 * time.Second // parsing and sending after the source read
)

// Options configures the servers.
type Options struct {
	Logger    *slog.Logger
	Recorder  proxy.Recorder
	AccessLog bool
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

// Start validates the web configuration files, binds every listener address,
// then serves them all. Nothing is served unless every listener could be
// set up: on error, already bound addresses are released.
func Start(cfg *config.Config, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// 1. Web configuration files: report every invalid one at once.
	var problems []string
	for _, l := range cfg.Listeners {
		if err := web.Validate(l.WebConfigFile); err != nil {
			problems = append(problems, fmt.Sprintf("listener %q: web_config_file %s: %s",
				l.Name, l.WebConfigFile, oneLine(err)))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid web configuration: %s", strings.Join(problems, "; "))
	}
	for _, l := range cfg.Listeners {
		if clear, err := basicAuthWithoutTLS(l.WebConfigFile); err == nil && clear {
			logger.Warn("basic authentication without TLS: credentials travel in clear text",
				"listener", l.Name, "web_config_file", l.WebConfigFile)
		}
	}

	// 2. Handlers.
	handlers := make([]http.Handler, len(cfg.Listeners))
	for i, l := range cfg.Listeners {
		h, err := proxy.NewHandler(l, proxy.Options{
			Logger:    logger,
			Recorder:  opts.Recorder,
			AccessLog: opts.AccessLog,
		})
		if err != nil {
			return nil, err
		}
		handlers[i] = h
	}

	// 3. Bind every address (or take every systemd socket) before serving
	// any, so that a port conflict fails the whole startup.
	sockets, err := takeSystemdSockets(cfg.Listeners, logger)
	if err != nil {
		return nil, err
	}
	s := &Server{logger: logger, errc: make(chan error, len(cfg.Listeners))}
	for i, l := range cfg.Listeners {
		var ln net.Listener
		if name, ok := config.SystemdSocketName(l.Listen); ok {
			ln = sockets[name]
		} else if ln, err = net.Listen("tcp", l.Listen); err != nil {
			s.closeListeners()
			closeAll(sockets)
			return nil, fmt.Errorf("listener %q: %w", l.Name, err)
		}
		s.listeners = append(s.listeners, &listener{
			name: l.Name,
			ln:   ln,
			srv:  newHTTPServer(handlers[i], l, logger),
		})
	}

	// 4. Serve.
	for i, l := range s.listeners {
		webConfig := cfg.Listeners[i].WebConfigFile
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

func newHTTPServer(h http.Handler, l config.Listener, logger *slog.Logger) *http.Server {
	var maxTimeout time.Duration
	for _, r := range l.Routes {
		maxTimeout = max(maxTimeout, r.Limits.Timeout)
	}
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readHeaderTimeout,
		WriteTimeout:      maxTimeout + writeMargin,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// TLS handshake failures (wrong or missing client certificate)
		// are security relevant: log them.
		ErrorLog: slog.NewLogLogger(logger.With("listener", l.Name).Handler(), slog.LevelWarn),
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
func takeSystemdSockets(listeners []config.Listener, logger *slog.Logger) (map[string]net.Listener, error) {
	wanted := map[string]string{} // socket name -> listener name
	for _, l := range listeners {
		if name, ok := config.SystemdSocketName(l.Listen); ok {
			wanted[name] = l.Name
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

// webConfigSummary holds the web configuration keys that decide whether TLS
// is enabled (same rule as exporter-toolkit's TLSConfig.IsEnabled) and
// whether basic authentication users are defined.
type webConfigSummary struct {
	TLS struct {
		Cert           string `yaml:"cert"`
		Key            string `yaml:"key"`
		CertFile       string `yaml:"cert_file"`
		KeyFile        string `yaml:"key_file"`
		ClientCA       string `yaml:"client_ca"`
		ClientCAFile   string `yaml:"client_ca_file"`
		ClientAuthType string `yaml:"client_auth_type"`
	} `yaml:"tls_server_config"`
	Users map[string]string `yaml:"basic_auth_users"`
}

// basicAuthWithoutTLS reports whether a web configuration defines basic
// authentication users without enabling TLS. The file was validated by
// exporter-toolkit beforehand; unknown keys are ignored here.
func basicAuthWithoutTLS(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var c webConfigSummary
	if err := yaml.Unmarshal(data, &c); err != nil {
		return false, err
	}
	t := c.TLS
	tlsEnabled := t.Cert != "" || t.Key != "" || t.CertFile != "" || t.KeyFile != "" ||
		t.ClientCA != "" || t.ClientCAFile != "" || t.ClientAuthType != ""
	return len(c.Users) > 0 && !tlsEnabled, nil
}

// oneLine keeps an error on a single log line.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
