// Package server runs one HTTP server per configured listener, with TLS,
// mTLS and basic authentication handled by prometheus/exporter-toolkit.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/errfmt"
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
	// successes keeps the verified credentials of each listener name
	// across its restarts on reload. Keys cover the stored hash, so a
	// changed web configuration never reuses a stale success.
	successes map[string]*successCache

	serving  sync.WaitGroup // web.Serve goroutines
	draining sync.WaitGroup // listeners stopped by a reload
}

type listener struct {
	settings listenerSettings
	auth     *authHandler
	spec     spec
	ln       net.Listener
	srv      *http.Server
	handler  *swapHandler
	// accept is ln as served: drain stops it before shutting srv down.
	accept *handoffListener
	// fresh tracks the connections that have not sent a request yet.
	fresh *freshConns
	// served is closed when srv stops serving: every connection it
	// accepted is then tracked by fresh.
	served chan struct{}
	// allowed holds the allowed_networks of the listener, nil for every
	// address. A reload keeping the listener replaces it.
	allowed atomic.Pointer[[]netip.Prefix]
	// refused reports a connection refused by allowed_networks.
	refused func(remote string)
}

// listenerSettings are the parts of a web configuration that apply when a
// listener starts. A reload restarts a listener whose settings changed,
// even if its web configuration file path did not.
type listenerSettings struct {
	tls       bool
	http2     bool // only meaningful with TLS
	rateLimit webRateLimit
	// basicAuth: started with basic_auth_users, which must then stay set
	// (fail closed) until a reload.
	basicAuth bool
	// mtls holds the client certificate settings, fixed while the listener
	// runs: a file that differs refuses new connections until a reload,
	// which restarts the listener and so closes the connections accepted
	// under the previous settings.
	mtls mtlsSettings
	// clientCA is the SHA-256 of the client CA content. Its content may
	// change while running (CA rotation); a reload with a new content
	// restarts the listener.
	clientCA [sha256.Size]byte
}

// mtlsSettings are the client certificate settings of a web configuration.
type mtlsSettings struct {
	clientAuth  string // normalized client_auth_type
	clientCA    bool   // a client CA is configured (file or inline)
	allowedSANs string // sorted client_allowed_sans, quoted: unambiguous
}

func mtlsOf(tc *web.TLSConfig) mtlsSettings {
	if !tc.IsEnabled() {
		return mtlsSettings{}
	}
	return mtlsSettings{
		clientAuth:  webconfig.NormalizeClientAuth(tc.ClientAuth),
		clientCA:    tc.ClientCAs != "" || tc.ClientCAsText != "",
		allowedSANs: quotedSANs(tc.ClientAllowedSans),
	}
}

// quotedSANs encodes a client_allowed_sans list for comparison: sorted and
// quoted, so that no two lists share an encoding; empty when unset.
func quotedSANs(sans []string) string {
	if len(sans) == 0 {
		return ""
	}
	return fmt.Sprintf("%q", slices.Sorted(slices.Values(sans)))
}

func settingsOf(wc *web.Config) listenerSettings {
	tc := wc.TLSConfig
	tlsEnabled := tc.IsEnabled()
	s := listenerSettings{
		tls:       tlsEnabled,
		http2:     tlsEnabled && wc.HTTPConfig.HTTP2,
		rateLimit: webRateLimit{interval: wc.RateLimiterConfig.Interval, burst: wc.RateLimiterConfig.Burst},
		basicAuth: len(wc.Users) > 0,
		mtls:      mtlsOf(&tc),
	}
	if !tlsEnabled {
		return s
	}
	ca := []byte(tc.ClientCAsText)
	if tc.ClientCAs != "" {
		if data, err := os.ReadFile(tc.ClientCAs); err == nil {
			ca = data
		} else {
			ca = []byte("unreadable: " + err.Error())
		}
	}
	s.clientCA = sha256.Sum256(ca)
	return s
}

// errClientAuthChanged refuses new TLS connections while the client
// certificate settings of the web configuration differ from those the
// listener started with: a file half-written or changed while running
// never lets a client in under other rules. Changing them takes a reload.
var errClientAuthChanged = errors.New("client certificate settings (client_auth_type, client CA, client_allowed_sans) " +
	"differ from those the listener started with: fix the file, or reload to apply them " +
	"(restart the service if they are weaker)")

// checkClientAuth refuses a web configuration whose client certificate
// settings differ from those of the listener.
func (l *listener) checkClientAuth(tc *web.TLSConfig) error {
	if mtlsOf(tc) != l.settings.mtls {
		return errClientAuthChanged
	}
	return nil
}

// tlsConfigFor builds the TLS configuration of a new connection: the
// client certificate settings must be those the listener started with, then
// serverTLSConfig applies.
func (l *listener) tlsConfigFor(c *web.Config) (*tls.Config, error) {
	if err := l.checkClientAuth(&c.TLSConfig); err != nil {
		return nil, err
	}
	// The listener offers HTTP/2 as set when it started, whatever the file
	// says now: its ciphers must carry it.
	withListenerHTTP2 := *c
	withListenerHTTP2.HTTPConfig.HTTP2 = l.settings.http2
	if err := webconfig.ValidateHTTP2Ciphers(&withListenerHTTP2); err != nil {
		return nil, err
	}
	return serverTLSConfig(c)
}

// serverTLSConfig builds a TLS configuration from c with exporter-toolkit,
// then applies exporter_proxy's rules: a client CA pool with at least one
// certificate (checked on the pool built from the single read of the file),
// a server certificate within its validity dates, loaded once and pinned in
// the configuration (so that every handshake of the connection, TLS 1.3
// session resumption included, goes through this check), and
// client_allowed_sans also on resumption.
func serverTLSConfig(c *web.Config) (*tls.Config, error) {
	cfg, err := web.ConfigToTLSConfig(&c.TLSConfig)
	if err != nil {
		return nil, err
	}
	if cfg.ClientCAs != nil && cfg.ClientCAs.Equal(x509.NewCertPool()) {
		return nil, errors.New("the client CA contains no certificate: every client would be refused")
	}
	if cfg.GetCertificate != nil {
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			return nil, err
		}
		if err := checkCertDates(cert, time.Now()); err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{*cert}
		cfg.GetCertificate = nil
	}
	restrictSANsOnResumption(cfg, c.TLSConfig)
	return cfg, nil
}

// errCertDates marks a server certificate chain outside its validity
// dates.
var errCertDates = errors.New("server certificate outside its validity dates")

// checkCertDates refuses a server certificate (the leaf) outside its
// validity dates: clients would reject it, and the failure would look like
// theirs. Intermediates are not checked: chains commonly carry an expired
// cross-signed certificate that clients skip by building another path to
// their trust store (only --check warns about them).
func checkCertDates(cert *tls.Certificate, now time.Time) error {
	if len(cert.Certificate) == 0 {
		return errors.New("no server certificate")
	}
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	switch {
	case now.After(c.NotAfter):
		return fmt.Errorf("%w: %q expired on %s", errCertDates, c.Subject, c.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(c.NotBefore):
		return fmt.Errorf("%w: %q is not valid before %s", errCertDates, c.Subject, c.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// restrictSANsOnResumption also checks client_allowed_sans when a client
// resumes a TLS session: exporter-toolkit checks them in
// VerifyPeerCertificate, which crypto/tls skips on resumption.
// VerifyConnection runs on every handshake.
//
// It also refuses a client without a certificate when client_allowed_sans
// is set: exporter-toolkit's check would panic on it (certificate optional,
// as with VerifyClientCertIfGiven).
func restrictSANsOnResumption(cfg *tls.Config, tc web.TLSConfig) {
	if tc.ClientAllowedSans == nil {
		return
	}
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("client_allowed_sans requires a client certificate")
		}
		return tc.VerifyPeerCertificate(rawCerts, chains)
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("client_allowed_sans requires a client certificate")
		}
		return tc.VerifyPeerCertificate([][]byte{cs.PeerCertificates[0].Raw}, nil)
	}
}

// running returns the settings l enforces now: the start-time settings,
// with basic authentication required once users were seen while running
// (fail closed).
func (l *listener) running() listenerSettings {
	s := l.settings
	s.basicAuth = l.auth.usersSeen.Load()
	return s
}

// weakens reports what next removes of the protection l enforces now.
func (l *listener) weakens(next listenerSettings) []string {
	var lost []string
	if l.auth.usersSeen.Load() && !next.basicAuth {
		lost = append(lost, "basic authentication")
	}
	cur, nxt := l.settings.mtls, next.mtls
	curRequired, curVerified := webconfig.ClientCertPolicy(cur.clientAuth)
	required, verified := webconfig.ClientCertPolicy(nxt.clientAuth)
	if (curRequired && !required) || (curVerified && !verified) ||
		(cur.clientCA && !nxt.clientCA) || (cur.allowedSANs != "" && nxt.allowedSANs == "") {
		lost = append(lost, "client certificate requirements")
	}
	if l.settings.tls && !next.tls {
		lost = append(lost, "TLS")
	}
	return lost
}

// spec describes one server: a configured listener or the metrics endpoint.
type spec struct {
	name         string
	listen       string
	webConfig    string
	handler      http.Handler
	writeTimeout time.Duration
	allowed      []netip.Prefix // allowed_networks, nil for every address
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

// store installs the handler of sp and returns the previous state, nil the
// first time.
func (sh *swapHandler) store(sp spec) *handlerState {
	return sh.cur.Swap(&handlerState{h: sp.handler, writeTimeout: sp.writeTimeout})
}

// retire closes the idle upstream connections of a handler replaced by a
// reload: now, then once its last requests are over (bounded by its write
// timeout), since connections in use go back to its pool when they end.
func retire(old *handlerState) {
	if old == nil {
		return
	}
	closeIdle(old.h)
	time.AfterFunc(old.writeTimeout, func() { closeIdle(old.h) })
}

// closeIdle closes the upstream connections of h that are idle now, instead
// of leaving them open until their idle timeout.
func closeIdle(h http.Handler) {
	if c, ok := h.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
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
		successes: map[string]*successCache{},
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
//   - a listener with the same name, address, web configuration file and
//     start-time settings (TLS, HTTP/2, rate_limit) keeps its socket and
//     connections; its routes and limits are swapped;
//   - a listener whose address is already served (web configuration file
//     or its start-time settings changed, listener renamed) gets a
//     duplicate of the socket, so the port is never closed, and the
//     previous server is stopped gracefully;
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
		l         *listener
		sp        spec
		basicAuth bool   // the web configuration has users
		tlsErr    error  // TLS settings checked like a new connection
		tlsGen    uint64 // TLS health generation before the check
	}
	var swaps []swap
	var started []*listener
	var weakened []string // listeners whose protection the reload would lower
	// replaced maps a listener stopped by this reload to the listener
	// taking its place: on the same address, or else with the same name
	// elsewhere (an address match wins).
	type replacement struct {
		l      *listener
		byAddr bool
	}
	replaced := map[*listener]replacement{}
	kept := map[string]bool{}
	for _, sp := range specs {
		cur := s.listeners[sp.name]
		if cur != nil && cur.spec.listen == sp.listen && cur.spec.webConfig == sp.webConfig {
			// Read before the file: a handshake failing on a file changed
			// after this read is not cleared by the check below.
			var tlsGen uint64
			if h := cur.auth.tlsHealth; h != nil {
				tlsGen = h.generation()
			}
			wc, err := webconfig.Load(sp.webConfig)
			if err != nil {
				s.abortReload(started)
				return fmt.Errorf("listener %q: %w", sp.name, err)
			}
			// Compared with what the listener enforces now, including what
			// was seen while running (fail closed): a different file
			// restarts the listener with it, if it does not weaken it.
			// Users in the file are required by requests anyway (usersSeen
			// is set by the first one): not a reason to restart.
			running, next := cur.running(), settingsOf(wc)
			running.basicAuth = running.basicAuth || next.basicAuth
			if next == running {
				if sp.allowed != nil && cur.ln.Addr().Network() == "unix" {
					s.abortReload(started)
					return fmt.Errorf("listener %q: allowed_networks does not apply to a Unix socket (%s)", sp.name, cur.ln.Addr())
				}
				var tlsErr error
				if next.tls {
					_, tlsErr = cur.tlsConfigFor(wc)
				}
				swaps = append(swaps, swap{cur, sp, next.basicAuth, tlsErr, tlsGen})
				kept[sp.name] = true
				continue
			}
			// TLS, HTTP/2, rate_limit or the presence of basic_auth_users
			// changed in the same file: restart the listener on its
			// socket, below.
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
			s.abortReload(started)
			return fmt.Errorf("listener %q: %w", sp.name, err)
		}
		l, err := s.newListener(sp, ln)
		if err != nil {
			_ = ln.Close()
			s.abortReload(started)
			return err
		}
		// The previous server on this address, whatever its name (renamed
		// or swapped listeners): clients of that port lose its protection.
		// Else the previous server of this name, moved to a new address.
		prev := byListen[sp.listen]
		if prev == nil {
			prev = cur
		}
		if prev != nil {
			if lost := prev.weakens(l.settings); len(lost) > 0 {
				weakened = append(weakened, fmt.Sprintf("listener %q: %s", sp.name, strings.Join(lost, " and ")))
			}
			byAddr := byListen[sp.listen] == prev
			if r, ok := replaced[prev]; !ok || byAddr || !r.byAddr {
				replaced[prev] = replacement{l, byAddr}
			}
		}
		started = append(started, l)
	}
	if len(weakened) > 0 {
		// A web configuration caught empty or half-written must not lower
		// authentication: a reload never does. Lowering it on purpose takes
		// a restart.
		s.abortReload(started)
		return fmt.Errorf("the reload would weaken authentication (%s): fix the web configuration, "+
			"or restart the service to apply it", strings.Join(weakened, "; "))
	}

	// Commit: nothing below can fail.
	for _, sw := range swaps {
		sw.l.spec = sw.sp
		sw.l.allowed.Store(&sw.sp.allowed)
		retire(sw.l.handler.store(sw.sp))
		if sw.basicAuth {
			// Users found by the reload are required from now on, like
			// users seen by a request (fail closed).
			sw.l.auth.usersSeen.Store(true)
		}
		// The TLS state checked by this reload replaces the previous one,
		// reported by ReportTLSHealth once the metrics are reset.
		if h := sw.l.auth.tlsHealth; h != nil {
			if sw.tlsErr != nil {
				h.markFailing()
			} else {
				h.markHealthySince(sw.tlsGen)
			}
		}
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
			// Until it is shut down, the stopped server may still answer
			// requests on connections opened before, behind its own
			// authentication layer. It serves the routes, authorize lists
			// and allowed_networks of its replacement only when that layer
			// enforces what the replacement does (same web configuration
			// file, same TLS and client certificate settings); otherwise it
			// answers 503, never the routes this reload removed nor new
			// routes under the previous authentication.
			if r, ok := replaced[l]; ok && sameAuthentication(l, r.l) {
				l.allowed.Store(&r.l.spec.allowed)
				retire(l.handler.store(r.l.spec))
			} else {
				retire(l.handler.store(spec{handler: removedListener{}, writeTimeout: writeMargin}))
			}
			s.drain(l)
		}
	}
	s.listeners = next
	s.pruneSuccesses()
	return nil
}

// ReportTLSHealth reports again the TLS listeners whose settings fail, after
// the metrics were reset by a configuration load (startup or reload), so
// that the failure shows from the start instead of at the next handshake.
func (s *Server) ReportTLSHealth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		if l.auth.tlsHealth != nil {
			l.auth.tlsHealth.reportFailing()
		}
	}
}

// abortReload closes the listeners started by a failed reload and forgets
// what it prepared for them. Called with s.mu held.
func (s *Server) abortReload(started []*listener) {
	closeListeners(started)
	s.pruneSuccesses()
}

// pruneSuccesses forgets the verified credentials of listeners that are not
// running. Called with s.mu held.
func (s *Server) pruneSuccesses() {
	for name := range s.successes {
		if _, ok := s.listeners[name]; !ok {
			delete(s.successes, name)
		}
	}
}

// prepare builds the handlers of cfg and validates the web configuration
// files, reporting every invalid one at once.
func (s *Server) prepare(cfg *config.Config) ([]spec, error) {
	var specs []spec
	if s.opts.MetricsHandler != nil {
		handler := s.opts.MetricsHandler
		if cfg.Metrics.ServiceDiscovery != nil {
			handler = &sdHandler{s: s, cfg: cfg, next: handler}
		}
		specs = append(specs, spec{
			name:         MetricsListener,
			listen:       cfg.Metrics.Listen,
			webConfig:    cfg.Metrics.WebConfigFile,
			handler:      handler,
			writeTimeout: metricsWriteTimeout,
			allowed:      cfg.Metrics.AllowedNetworks,
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
			allowed:      l.AllowedNetworks,
		})
	}

	var problems []string
	for _, sp := range specs {
		err := web.Validate(sp.webConfig)
		var wc *web.Config
		if err == nil {
			// exporter_proxy's own rules, checked for every file now so that
			// all problems are reported at once.
			wc, err = webconfig.Load(sp.webConfig)
		}
		if err == nil && wc.TLSConfig.IsEnabled() {
			// What every new connection would check. A certificate outside
			// its dates only stops that listener's TLS connections (as a
			// server-side failure): logged, not refused, so that the other
			// listeners and the metrics endpoint keep running.
			_, err = serverTLSConfig(wc)
			if errors.Is(err, errCertDates) {
				s.logger.Error("server certificate outside its validity dates: new TLS connections will be refused",
					"listener", sp.name, "web_config_file", sp.webConfig, "err", errfmt.OneLine(err))
				err = nil
			}
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("listener %q: web_config_file %s: %s",
				sp.name, sp.webConfig, errfmt.OneLine(err)))
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
	for _, l := range cfg.Listeners {
		wc, err := webconfig.Read(l.WebConfigFile)
		if err != nil {
			continue
		}
		for _, r := range l.Routes {
			if r.Authorize == nil {
				continue
			}
			for _, w := range wc.AuthorizeWarnings(len(r.Authorize.Users), len(r.Authorize.ClientSANs)) {
				s.logger.Warn(w, "listener", l.Name, "route", r.Path, "web_config_file", l.WebConfigFile)
			}
		}
	}
	return specs, nil
}

// newListener prepares the HTTP server of sp on ln: TLS settings and the
// authentication layer come from its web configuration file. It does not
// serve yet.
func (s *Server) newListener(sp spec, ln net.Listener) (*listener, error) {
	if sp.allowed != nil && ln.Addr().Network() == "unix" {
		// Unix socket clients have no address to check: refuse rather
		// than silently allow them all.
		return nil, fmt.Errorf("listener %q: allowed_networks does not apply to a Unix socket (%s)", sp.name, ln.Addr())
	}
	wc, err := webconfig.Load(sp.webConfig)
	if err != nil {
		return nil, fmt.Errorf("listener %q: %w", sp.name, err)
	}

	settings := settingsOf(wc)
	successes := s.successes[sp.name]
	if successes == nil {
		successes = newSuccessCache(successCacheSize)
		s.successes[sp.name] = successes
	}
	clientLogs, serverLogs := newLogGate(), newLogGate()
	sh := newSwapHandler(sp)
	auth := newAuthHandler(authOptions{
		listener:     sp.name,
		webConfig:    sp.webConfig,
		rateLimit:    settings.rateLimit,
		requireUsers: settings.basicAuth,
		tls:          settings.tls,
		successes:    successes,
		clientLogs:   clientLogs,
		serverLogs:   serverLogs,
	}, sh, s.logger, s.recorder())
	srv := &http.Server{
		Handler: auth,
		// "OPTIONS *" goes through authentication too, instead of an
		// automatic empty 200.
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            readHeaderTimeout,
		ReadTimeout:                  readHeaderTimeout,
		// Baseline until the handler sets the per-request deadline.
		WriteTimeout:   writeMargin,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
		// TLS handshake failures are counted and logged as such.
		ErrorLog: log.New(&serverErrorLog{listener: sp.name, logger: s.logger, rec: s.recorder(),
			clientLogs: clientLogs, serverLogs: serverLogs}, "", 0),
	}

	fresh := &freshConns{m: map[net.Conn]struct{}{}}
	srv.ConnState = fresh.track
	l := &listener{settings: settings, auth: auth, spec: sp, ln: ln, srv: srv, handler: sh,
		accept: &handoffListener{Listener: ln}, fresh: fresh, served: make(chan struct{})}
	l.allowed.Store(&sp.allowed)
	auth.allows = func(remote string) bool { return l.allowsRemote(remote) }
	logger := s.logger.With("listener", sp.name)
	l.refused = func(remote string) {
		s.recorder().AuthFailed(sp.name, proxy.AuthNetworkNotAllowed)
		logger.Log(context.Background(), clientLogs.level(slog.LevelWarn),
			"connection refused: client address not in allowed_networks", "remote", remote)
	}
	if !settings.tls {
		return l, nil
	}

	tlsCfg, err := web.ConfigToTLSConfig(&wc.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("listener %q: web_config_file %s: %w", sp.name, sp.webConfig, err)
	}
	nextProtos := []string{"http/1.1"}
	if settings.http2 {
		nextProtos = []string{"h2", "http/1.1"}
	} else {
		// A non-nil empty map disables HTTP/2 in net/http.
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	tlsCfg.NextProtos = nextProtos
	webConfig, logger := sp.webConfig, s.logger.With("listener", sp.name)
	var health *tlsHealth
	// fail reports a failure of the server's TLS settings, and returns the
	// error marked for serverErrorLog: the server, not the client, failed
	// the handshake.
	fail := func(err error) error {
		health.failed()
		logger.Log(context.Background(), serverLogs.level(slog.LevelError), "cannot load TLS settings for a new connection",
			"web_config_file", webConfig, "err", errfmt.OneLine(err))
		return fmt.Errorf("%s: %w", serverTLSUnavailable, err)
	}
	health = newTLSHealth(func() error {
		c, err := webconfig.LoadForRequest(webConfig)
		if err != nil {
			return err
		}
		_, err = l.tlsConfigFor(c)
		return err
	}, func(ok bool) {
		if !auth.retired.Load() {
			s.recorder().WebConfigRead(sp.name, true, ok)
		}
	})
	auth.tlsHealth = health
	if _, err := l.tlsConfigFor(wc); err != nil {
		// Logged by prepare (a certificate outside its dates). Reported by
		// ReportTLSHealth once the start or reload is applied, not now: an
		// aborted reload must not raise an alarm for a listener that keeps
		// running.
		health.markFailing()
	}
	// Certificates, key and client CA are re-read on every new connection,
	// like exporter-toolkit: renewed files apply without restart.
	tlsCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		gen := health.generation()
		// The client CA is checked on the pool built from a single read of
		// it (tlsConfigFor), not read twice.
		c, err := webconfig.LoadForRequest(webConfig)
		if err != nil {
			return nil, fail(err)
		}
		cfg, err := l.tlsConfigFor(c)
		if err != nil {
			return nil, fail(err)
		}
		health.succeededSince(gen)
		cfg.NextProtos = nextProtos
		return cfg, nil
	}
	srv.TLSConfig = tlsCfg
	return l, nil
}

func (s *Server) recorder() proxy.Recorder {
	if s.opts.Recorder == nil {
		return proxy.NopRecorder{}
	}
	return s.opts.Recorder
}

// serve serves l in the background. Called with s.mu held or before s is
// shared: the goroutine only uses values copied here, since a reload may
// update l.spec meanwhile.
func (s *Server) serve(l *listener) {
	name, tlsEnabled, srv, ln := l.spec.name, l.settings.tls, l.srv, l.ln
	var served net.Listener = networkFilter{l.accept, l}
	if ln.Addr().Network() == "unix" {
		served = unixClientsListener{l.accept}
	}
	s.logger.Info("listening", "listener", name, "address", ln.Addr().String(), "tls", tlsEnabled)
	s.serving.Add(1)
	go func() {
		defer s.serving.Done()
		defer close(l.served)
		var err error
		if tlsEnabled {
			err = srv.ServeTLS(served, "", "")
		} else {
			err = srv.Serve(served)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Serve may fail before taking ownership of ln (HTTP/2 setup):
			// release the socket.
			_ = ln.Close()
			select {
			case s.errc <- fmt.Errorf("listener %q: %w", name, err):
			default: // an error is already pending
			}
		}
	}()
}

// drain stops l gracefully in the background, then closes its idle
// upstream connections. Called with s.mu held.
//
// l first stops accepting, then its connections that have not sent a
// request yet get the time to send one, and only then is its server shut
// down: net/http closes, without any response, a connection whose request
// is read after Shutdown started. With a socket shared with the listener
// replacing l (reload), l may have accepted a connection just before.
func (s *Server) drain(l *listener) {
	name, srv, handler := l.spec.name, l.srv, l.handler
	l.auth.retired.Store(true)
	s.draining.Add(1)
	go func() {
		defer s.draining.Done()
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		l.accept.stop()
		// Serve tracks a connection Accept returned before it accepts
		// again: once it returned, every accepted connection is in fresh.
		select {
		case <-l.served:
		case <-ctx.Done():
		}
		l.fresh.wait(ctx, readHeaderTimeout)
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
			s.logger.Warn("listener stopped with requests still running", "listener", name, "err", err)
		}
		closeIdle(handler.cur.Load().h)
	}()
}

// networkFilter refuses, as soon as they are accepted, the connections
// whose client address is outside the listener's allowed_networks: before
// any TLS handshake or request. An address that cannot be parsed is
// refused.
type networkFilter struct {
	net.Listener
	l *listener
}

func (f networkFilter) Accept() (net.Conn, error) {
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if f.l.allows(c.RemoteAddr()) {
			return c, nil
		}
		_ = c.Close()
		f.l.refused(remoteIP(c.RemoteAddr()))
	}
}

// allows reports whether addr is in the listener's allowed_networks.
func (l *listener) allows(addr net.Addr) bool { return l.allowsRemote(addr.String()) }

// allowsRemote is allows for the RemoteAddr of a request.
func (l *listener) allowsRemote(remote string) bool {
	allowed := l.allowed.Load()
	if allowed == nil || *allowed == nil {
		return true
	}
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap().WithZone("")
	for _, p := range *allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP returns the address of a client without its port, for logs.
func remoteIP(addr net.Addr) string {
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap.Addr().Unmap().String()
	}
	return addr.String()
}

// sameAuthentication reports whether the authentication layer of old
// enforces what that of next does: the same web configuration file (read
// on every request: users added since apply), the same TLS and client
// certificate settings and the same client CA content (connections were
// verified against it).
func sameAuthentication(old, next *listener) bool {
	return old.spec.webConfig == next.spec.webConfig && old.settings.tls == next.settings.tls &&
		old.settings.mtls == next.settings.mtls && old.settings.clientCA == next.settings.clientCA
}

// removedListener answers the requests a removed listener still gets on
// connections opened before the reload, while it shuts down.
type removedListener struct{}

func (removedListener) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Connection", "close")
	http.Error(w, "listener removed by a configuration reload", http.StatusServiceUnavailable)
}

// handoffListener is a listener whose server can stop accepting before
// shutting down: Accept then returns http.ErrServerClosed, so that Serve
// returns without reporting a failure. Close is idempotent: Shutdown
// closing it again does not fail.
type handoffListener struct {
	net.Listener
	stopped  atomic.Bool
	once     sync.Once
	closeErr error
}

func (h *handoffListener) Accept() (net.Conn, error) {
	c, err := h.Listener.Accept()
	if err != nil && h.stopped.Load() {
		return nil, http.ErrServerClosed
	}
	return c, err
}

func (h *handoffListener) Close() error {
	h.once.Do(func() { h.closeErr = h.Listener.Close() })
	return h.closeErr
}

// stop stops accepting. A socket shared with another listener (dupListener)
// stays open: that listener accepts its connections from now on.
func (h *handoffListener) stop() {
	h.stopped.Store(true)
	_ = h.Close()
}

// freshConns tracks the connections of a server that have not sent a
// request yet (http.StateNew, TLS handshake included).
type freshConns struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

// track is the http.Server ConnState hook.
func (f *freshConns) track(c net.Conn, st http.ConnState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st == http.StateNew {
		f.m[c] = struct{}{}
	} else {
		delete(f.m, c)
	}
}

func (f *freshConns) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

// wait returns once no connection is fresh, after limit (a client must
// send its request headers within readHeaderTimeout anyway), or when ctx
// ends.
func (f *freshConns) wait(ctx context.Context, limit time.Duration) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for f.count() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-tick.C:
		}
	}
}

// unixClientsListener gives every client of a Unix socket listener the
// same remote address, "unix". A client may bind its socket to any path,
// which would otherwise show as its remote address in logs and could
// imitate the server-side handshake marker; those paths identify nothing.
type unixClientsListener struct{ net.Listener }

func (l unixClientsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return unixClientConn{c}, nil
}

type unixClientConn struct{ net.Conn }

func (unixClientConn) RemoteAddr() net.Addr { return unixRemote{} }

// CloseWrite keeps net/http's graceful half-close before closing a
// connection, which the wrapper would otherwise hide.
func (c unixClientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type unixRemote struct{}

func (unixRemote) Network() string { return "unix" }
func (unixRemote) String() string  { return "unix" }

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
	type running struct {
		name    string
		srv     *http.Server
		handler *swapHandler
	}
	s.mu.Lock()
	listeners := make([]running, 0, len(s.listeners))
	for _, l := range s.listeners {
		listeners = append(listeners, running{l.spec.name, l.srv, l.handler})
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
				errs = append(errs, fmt.Sprintf("listener %q: %v", l.name, err))
				mu.Unlock()
			}
			closeIdle(l.handler.cur.Load().h)
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
	// Called even when no listener uses systemd: sockets passed anyway are
	// closed and reported below.
	passed, err := systemdListeners()
	if err != nil {
		if len(wanted) == 0 {
			logger.Warn("cannot read the sockets passed by systemd", "err", err)
			return nil, nil
		}
		return nil, fmt.Errorf("systemd socket activation: %w", err)
	}
	sockets := make(map[string]net.Listener, len(wanted))
	var problems []string
	for name, lns := range passed {
		// Only TCP and Unix stream sockets can be served: datagram ones
		// fail on Accept, and Unix seqpacket ones would show the path a
		// client binds to as its address (see unixClientsListener).
		var stream, other []net.Listener
		for _, ln := range lns {
			switch {
			case ln == nil:
			case ln.Addr().Network() == "tcp" || ln.Addr().Network() == "unix":
				stream = append(stream, ln)
			default:
				other = append(other, ln)
			}
		}
		closeAll(nil, other...)
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
			problems = append(problems, fmt.Sprintf("listener %q: no systemd socket named %q (FileDescriptorName=; "+
				"a UDP socket, ListenDatagram=, is not passed as a listener)", listener, name))
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
