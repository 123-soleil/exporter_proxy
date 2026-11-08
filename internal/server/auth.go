package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	config_util "github.com/prometheus/common/config"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/123-soleil/exporter_proxy/internal/errfmt"
	"github.com/123-soleil/exporter_proxy/internal/proxy"
	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// Limits on password verifications that are not already known to succeed.
// bcrypt is deliberately slow (about 250 ms at cost 12): without a limit,
// random passwords would keep a CPU busy and delay legitimate scrapes.
const (
	// clientVerifyRate and clientVerifyBurst bound uncached bcrypt
	// verifications per client IP address: a brute force from one address
	// cannot use up the verifications of the other clients. Scrapers whose
	// credentials were already verified are served from the cache and
	// never limited.
	clientVerifyRate  = 2 // per second
	clientVerifyBurst = 5

	// verifyRate and verifyBurst bound uncached bcrypt verifications per
	// listener, all clients together: the last guard against an attack
	// from many addresses. About what one CPU verifies at cost 12.
	verifyRate  = 5 // per second
	verifyBurst = 10

	// maxPendingVerifications bounds the verifications running or waiting
	// for verifyMu: beyond it, requests get 429 instead of queuing, so a
	// queue never builds up when hashes cost more than the rate allows.
	maxPendingVerifications = 4

	// maxTrackedClients bounds the per-address limiters kept in memory.
	maxTrackedClients = 4096

	// successCacheSize bounds the cache of verified credentials. Only
	// valid credentials enter it, so an attacker cannot fill or evict it.
	successCacheSize = 1000

	// maxLoggedUserLen truncates user names in logs (client-supplied text).
	maxLoggedUserLen = 64

	// logRate and logBurst bound the lines a listener logs at their normal
	// level (warn or error), separately for client failures (refusals,
	// handshakes) and for server-side errors (518, TLS settings), so that
	// client noise never hides a server error; beyond, they are logged at
	// debug level, so that an attacker cannot flood the logs. Every refusal
	// is still counted in the metrics.
	logRate  = 1 // per second
	logBurst = 10
)

// StatusWebConfigUnreadable answers every request of a listener whose web
// configuration file cannot be read or parsed (unassigned 5xx code, so that
// it is told apart from upstream and proxy errors), with
// WebConfigUnreadableMessage as body.
const (
	StatusWebConfigUnreadable  = 518
	WebConfigUnreadableMessage = "web configuration unreadable"
)

// errUsersRemoved fails a web configuration that has no basic_auth_users
// while the listener started with some: a file emptied or truncated while
// being rewritten must not open the listener. Removing authentication on
// purpose takes a reload.
var errTLSAdded = errors.New("tls_server_config is set, while this listener serves plain HTTP: reload to enable TLS")

// removeAuthHint completes errUsersRemoved.
const removeAuthHint = "fix the file, or restart the service to remove authentication"

var errUsersRemoved = errors.New("basic_auth_users is missing or empty, while this listener requires basic authentication: " +
	removeAuthHint)

// fakeHash is compared against when the user does not exist and no
// configured hash gives a cost: bcrypt hash of "fakepassword" at cost 10,
// same value as exporter-toolkit.
const fakeHash = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi"

// fakeHashes caches, by bcrypt cost, the hash compared against when the
// user does not exist.
var fakeHashes sync.Map // int -> []byte

// bcryptMaxPassword is the length bcrypt cuts passwords to.
const bcryptMaxPassword = 72

// fakeHashFor returns a hash with the highest cost of the configured
// hashes, so that an unknown user takes as long as a known one with a wrong
// password (no user enumeration by timing). It is generated once per cost.
func fakeHashFor(users map[string]config_util.Secret) []byte {
	cost := 0
	for _, h := range users {
		if c, err := bcrypt.Cost([]byte(h)); err == nil && c > cost {
			cost = c
		}
	}
	if cost == 0 {
		return []byte(fakeHash)
	}
	if v, ok := fakeHashes.Load(cost); ok {
		return v.([]byte)
	}
	h, err := bcrypt.GenerateFromPassword([]byte("fakepassword"), cost)
	if err != nil {
		return []byte(fakeHash)
	}
	v, _ := fakeHashes.LoadOrStore(cost, h)
	return v.([]byte)
}

// tlsHealth tracks whether new TLS connections of a listener fail on its
// TLS settings. While they do, requests on connections already open check,
// at most once per second, whether the settings load again, so that the
// failure is not reported until the next handshake only.
type tlsHealth struct {
	mu      sync.Mutex
	failing bool
	gen     uint64 // bumped by every failed handshake

	limit *rate.Limiter
	// recheck loads the web configuration and its TLS settings like a new
	// connection would.
	recheck func() error
	// report records the state in the metrics. It is called with mu held,
	// so that the metric always follows the state.
	report func(ok bool)
}

func newTLSHealth(recheck func() error, report func(ok bool)) *tlsHealth {
	return &tlsHealth{limit: rate.NewLimiter(1, 1), recheck: recheck, report: report}
}

func (t *tlsHealth) failed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failing = true
	t.gen++
	t.report(false)
}

// markFailing records a failure without reporting it: the listener is not
// serving yet (its start or reload may still be aborted). ReportTLSHealth
// reports it once applied.
func (t *tlsHealth) markFailing() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failing = true
	t.gen++
}

// markHealthySince records that the TLS settings loaded when checked at
// generation gen, without reporting it (ReportTLSHealth only reports
// failures; a configuration load resets the metric). A handshake failing
// since keeps the failure: the file may have broken after the check. A
// failure from a handshake that read the file before the check keeps it
// too, until the next request rechecks it (recover) or the next handshake
// succeeds.
func (t *tlsHealth) markHealthySince(gen uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.gen != gen {
		return
	}
	t.failing = false
	t.gen++
}

// reportFailing reports the failure again, if any.
func (t *tlsHealth) reportFailing() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failing {
		t.report(false)
	}
}

// generation returns the count of failed handshakes, to pass to
// succeededSince.
func (t *tlsHealth) generation() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

// succeededSince records a successful handshake that started at generation
// gen, unless another handshake failed meanwhile: the file may have broken
// after this one read it.
func (t *tlsHealth) succeededSince(gen uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.gen != gen {
		return
	}
	t.failing = false
	t.report(true)
}

// recover rechecks the TLS settings while handshakes fail, and reports
// whether the failure is cleared. A handshake failing during the recheck
// keeps it: the recheck may have read the file before it broke.
func (t *tlsHealth) recover() bool {
	t.mu.Lock()
	failing, gen := t.failing, t.gen
	t.mu.Unlock()
	if !failing || !t.limit.Allow() {
		return false
	}
	err := t.recheck()
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		if t.failing {
			// Still failing: report it again, so that a reload resetting
			// the metrics does not hide it until the next handshake.
			t.report(false)
		}
		return false
	}
	if !t.failing || t.gen != gen {
		return false
	}
	t.failing = false
	t.report(true)
	return true
}

// logGate lowers log lines to debug level beyond logRate per listener.
type logGate struct{ l *rate.Limiter }

func newLogGate() *logGate { return &logGate{l: rate.NewLimiter(logRate, logBurst)} }

// level returns normal while under the rate, slog.LevelDebug beyond. A nil
// gate never lowers the level.
func (g *logGate) level(normal slog.Level) slog.Level {
	if g == nil || g.l.Allow() {
		return normal
	}
	return slog.LevelDebug
}

// authOptions configures an authHandler.
type authOptions struct {
	listener  string
	webConfig string
	// rateLimit is the rate_limit of the web configuration when the
	// listener started.
	rateLimit webRateLimit
	// tls: the listener serves TLS. A plain listener whose file enables TLS
	// fails closed until a reload, instead of serving in clear text.
	tls bool
	// requireUsers is set when the listener started with basic
	// authentication: a file without users then fails closed. It also
	// becomes set once users are seen while running.
	requireUsers bool
	// successes may be shared with a previous server of the same listener,
	// so that a restart on reload does not verify every scraper again.
	successes *successCache
	// clientLogs gates client failure lines, serverLogs server-side error
	// lines.
	clientLogs, serverLogs *logGate
}

// authHandler applies the web configuration of a listener to each request,
// like exporter-toolkit does, and reports every refusal:
//
//   - the file is re-read on every request: users, passwords and headers
//     change without restart;
//   - the optional rate_limit of the web configuration applies to all
//     requests (exporter-toolkit semantics);
//   - basic authentication when basic_auth_users is set, and always if it
//     was set when the listener started.
type authHandler struct {
	authOptions
	next   http.Handler
	logger *slog.Logger
	rec    proxy.Recorder

	// limiter is the rate_limit of the web configuration, fixed at start
	// like exporter-toolkit; nil when not configured.
	limiter *rate.Limiter
	// clientLimiters and verifyLimiter bound uncached bcrypt
	// verifications, per client address and per listener.
	clientLimiters *clientLimiters
	verifyLimiter  *rate.Limiter
	// verifyMu runs one bcrypt verification at a time, like
	// exporter-toolkit; pending holds a slot per verification running or
	// waiting for it.
	verifyMu sync.Mutex
	pending  chan struct{}
	// tlsHealth is set on TLS listeners.
	tlsHealth *tlsHealth
	// allows checks a client address against the listener's
	// allowed_networks on every request: a reload narrowing them refuses
	// connections opened before it at their next request. Nil: no check.
	allows func(remote string) bool
	// retired is set once the listener is replaced or stopped: requests
	// and handshakes it still finishes no longer report the web
	// configuration state, which belongs to the listener of the same name
	// now serving.
	retired atomic.Bool
	// flights runs a single verification for identical credentials sent
	// at the same time (several routes or scrapers starting together). The
	// per-client limit is charged to the first of them only: the others
	// carry the same valid-or-not credentials, so nothing is bypassed.
	flights singleflight.Group
	// usersSeen: basic authentication is required until the next reload,
	// whatever the file says (fail closed).
	usersSeen atomic.Bool
}

func newAuthHandler(o authOptions, next http.Handler, logger *slog.Logger, rec proxy.Recorder) *authHandler {
	if o.successes == nil {
		o.successes = newSuccessCache(successCacheSize)
	}
	if o.clientLogs == nil {
		o.clientLogs = newLogGate()
	}
	if o.serverLogs == nil {
		o.serverLogs = newLogGate()
	}
	h := &authHandler{
		authOptions:    o,
		next:           next,
		logger:         logger.With("listener", o.listener),
		rec:            rec,
		clientLimiters: newClientLimiters(clientVerifyRate, clientVerifyBurst, maxTrackedClients),
		verifyLimiter:  rate.NewLimiter(verifyRate, verifyBurst),
		pending:        make(chan struct{}, maxPendingVerifications),
	}
	if o.rateLimit.interval > 0 {
		h.limiter = rate.NewLimiter(rate.Every(o.rateLimit.interval), o.rateLimit.burst)
	}
	h.usersSeen.Store(o.requireUsers)
	return h
}

// webRateLimit is the rate_limit section of a web configuration.
type webRateLimit struct {
	interval time.Duration
	burst    int
}

// verifyResult is the outcome of a password verification.
type verifyResult int

const (
	verifyOK verifyResult = iota
	verifyInvalid
	verifyLimited
)

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.allows != nil && !h.allows(r.RemoteAddr) {
		if !h.retired.Load() {
			h.rec.AuthFailed(h.listener, proxy.AuthNetworkNotAllowed)
		}
		h.logger.Log(r.Context(), h.clientLogs.level(slog.LevelWarn),
			"request refused: client address no longer in allowed_networks, closing the connection",
			"remote", r.RemoteAddr)
		// HTTP/1.1 closes the connection after the answer; HTTP/2 sends
		// GOAWAY.
		w.Header().Set("Connection", "close")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	// Before reading the web configuration: refused requests cost nothing.
	if h.limiter != nil && !h.limiter.Allow() {
		h.refuse(w, r, proxy.AuthRateLimited, "", http.StatusTooManyRequests)
		return
	}

	c, err := webconfig.LoadForRequest(h.webConfig)
	if err == nil && !h.tls && c.TLSConfig.IsEnabled() {
		err = errTLSAdded
	}
	if err == nil {
		if len(c.Users) > 0 {
			h.usersSeen.Store(true)
		} else if h.usersSeen.Load() {
			err = errUsersRemoved
		}
	}
	if !h.retired.Load() {
		h.rec.WebConfigRead(h.listener, false, err == nil)
	}
	if err == nil && h.tlsHealth != nil {
		// While new TLS connections fail, check whether the settings load
		// again and report it now (recover records it), rather than at the
		// next handshake, which a scraper keeping its connection open may
		// not make for a long time.
		h.tlsHealth.recover()
	}
	if err != nil {
		h.logger.Log(r.Context(), h.serverLogs.level(slog.LevelError), "cannot load web configuration",
			"web_config_file", h.webConfig, "code", StatusWebConfigUnreadable, "err", errfmt.OneLine(err))
		http.Error(w, WebConfigUnreadableMessage, StatusWebConfigUnreadable)
		return
	}

	for k, v := range c.HTTPConfig.Header {
		w.Header().Set(k, v)
	}

	if len(c.Users) == 0 {
		h.next.ServeHTTP(w, r)
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		h.refuse(w, r, proxy.AuthMissingCredentials, "", http.StatusUnauthorized)
		return
	}
	hash, known := c.Users[user]

	// bcrypt only uses the first 72 bytes of a password: longer ones are
	// cut the same way here, so that suffixes added to a valid password do
	// not each fill an entry of the success cache.
	if len(pass) > bcryptMaxPassword {
		pass = pass[:bcryptMaxPassword]
	}
	// The key covers the stored hash: a password change in the web
	// configuration invalidates the cached success. The password itself is
	// never kept in memory.
	key := sha256.Sum256([]byte(user + "\x00" + string(hash) + "\x00" + pass))
	if known && h.successes.has(key) {
		h.next.ServeHTTP(w, r)
		return
	}

	switch h.verify(r, key, []byte(hash), known, c.Users, pass) {
	case verifyOK:
		h.next.ServeHTTP(w, r)
	case verifyLimited:
		h.refuse(w, r, proxy.AuthRateLimited, user, http.StatusTooManyRequests)
	default:
		h.refuse(w, r, proxy.AuthInvalidCredentials, user, http.StatusUnauthorized)
	}
}

// verify checks a password with bcrypt, within the limits. Requests sent at
// the same time with the same credentials share one verification and its
// result, without taking more of the limits.
func (h *authHandler) verify(r *http.Request, key [sha256.Size]byte, hash []byte, known bool, users map[string]config_util.Secret, pass string) verifyResult {
	v, _, _ := h.flights.Do(string(key[:]), func() (any, error) {
		if k := clientKey(r); k != "" && !h.clientLimiters.allow(k) || !h.verifyLimiter.Allow() {
			return verifyLimited, nil
		}
		select {
		case h.pending <- struct{}{}:
		default:
			return verifyLimited, nil
		}
		defer func() { <-h.pending }()

		h.verifyMu.Lock()
		defer h.verifyMu.Unlock()
		compared := hash
		if !known {
			compared = fakeHashFor(users)
		}
		if err := bcrypt.CompareHashAndPassword(compared, []byte(pass)); err != nil || !known {
			return verifyInvalid, nil
		}
		h.successes.add(key)
		return verifyOK, nil
	})
	return v.(verifyResult)
}

// refuse answers a refused request and reports it.
func (h *authHandler) refuse(w http.ResponseWriter, r *http.Request, reason proxy.AuthReason, user string, code int) {
	h.rec.AuthFailed(h.listener, reason)
	attrs := []any{"reason", string(reason), "remote", r.RemoteAddr, "path", r.URL.Path}
	if user != "" {
		if len(user) > maxLoggedUserLen {
			user = user[:maxLoggedUserLen] + "..."
		}
		attrs = append(attrs, "user", user)
	}
	level := slog.LevelDebug
	if reason == proxy.AuthRateLimited {
		// Under attack every attempt is rate limited: keep these at debug
		// level and rely on exporter_proxy_auth_failures_total.
		w.Header().Set("Retry-After", "1")
	} else {
		level = h.clientLogs.level(slog.LevelWarn)
	}
	h.logger.Log(r.Context(), level, "authentication refused", attrs...)
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="exporter_proxy"`)
	}
	http.Error(w, http.StatusText(code), code)
}

// successCache remembers credentials that passed bcrypt verification.
type successCache struct {
	mu   sync.Mutex
	max  int
	keys map[[sha256.Size]byte]struct{}
}

func newSuccessCache(maxEntries int) *successCache {
	return &successCache{max: maxEntries, keys: map[[sha256.Size]byte]struct{}{}}
}

func (c *successCache) has(k [sha256.Size]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.keys[k]
	return ok
}

func (c *successCache) add(k [sha256.Size]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keys) >= c.max {
		// Only valid credentials get here: reaching the bound means many
		// password changes; start over.
		clear(c.keys)
	}
	c.keys[k] = struct{}{}
}

// clientKey identifies the client for rate limiting: its IPv4 address, or
// the /64 network of its IPv6 address, since a single host usually owns a
// whole /64. It is empty when the client has no IP address (listener on a
// Unix socket passed by systemd): only the per-listener limit applies then,
// instead of one bucket shared by all clients.
func clientKey(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return addr.String()
	}
	return p.String()
}

// clientLimiters holds one rate limiter per client address.
type clientLimiters struct {
	mu    sync.Mutex
	limit rate.Limit
	burst int
	max   int
	m     map[string]*rate.Limiter
}

func newClientLimiters(limit rate.Limit, burst, maxEntries int) *clientLimiters {
	return &clientLimiters{limit: limit, burst: burst, max: maxEntries, m: map[string]*rate.Limiter{}}
}

// allow takes a token from the limiter of addr.
func (c *clientLimiters) allow(addr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.m[addr]
	if !ok {
		if len(c.m) >= c.max {
			c.evict()
		}
		l = rate.NewLimiter(c.limit, c.burst)
		c.m[addr] = l
	}
	return l.Allow()
}

// evict makes room: limiters with a full bucket are dropped first, since a
// new limiter behaves the same; if none is full, all are dropped (the
// per-listener limit still applies).
func (c *clientLimiters) evict() {
	now := time.Now()
	for addr, l := range c.m {
		if l.TokensAt(now) >= float64(c.burst) {
			delete(c.m, addr)
		}
	}
	if len(c.m) >= c.max {
		clear(c.m)
	}
}

// serverTLSUnavailable marks the handshake errors caused by the server's
// own TLS settings (web configuration, certificate, key or client CA that
// cannot be loaded), as opposed to a client failing the handshake.
const serverTLSUnavailable = "server TLS settings unavailable"

// serverErrorLog turns net/http server errors into structured log lines and
// counts TLS handshake failures caused by clients (wrong or missing client
// certificate, TLS version or cipher mismatch, plain HTTP clients, port
// scanners).
type serverErrorLog struct {
	listener string
	logger   *slog.Logger
	rec      proxy.Recorder
	// clientLogs gates client handshake failures and the net/http lines
	// clients can cause, serverLogs accept errors and panics, which client
	// noise must not hide.
	clientLogs, serverLogs *logGate
}

const tlsHandshakePrefix = "http: TLS handshake error from "

func (l *serverErrorLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	ctx := context.Background()
	if rest, ok := strings.CutPrefix(msg, tlsHandshakePrefix); ok {
		remote, detail, _ := strings.Cut(rest, ": ")
		// A prefix match: the marker starts the error returned by
		// GetConfigForClient, while client-chosen text (such as an ALPN
		// protocol name) can only appear later in other errors.
		// The remote address is never client-chosen text (an IP address,
		// or "unix" for Unix socket clients, see unixClientsListener), so
		// the client cannot put the marker at the start of the detail.
		if strings.HasPrefix(detail, serverTLSUnavailable+": ") {
			// Already logged and shown by exporter_proxy_web_config_read_error:
			// not a client failure.
			l.logger.Debug("TLS handshake refused, server TLS settings unavailable",
				"listener", l.listener, "remote", remote, "err", detail)
			return len(p), nil
		}
		l.rec.AuthFailed(l.listener, proxy.AuthTLSHandshake)
		l.logger.Log(ctx, l.clientLogs.level(slog.LevelWarn), "TLS handshake failed", "listener", l.listener,
			"reason", string(proxy.AuthTLSHandshake), "remote", remote, "err", detail)
		return len(p), nil
	}
	// Most net/http lines can be caused by clients (HTTP/2 GOAWAY, bad
	// preface, semicolons in queries...): they share the client budget.
	// Only accept errors and handler panics are the server's own.
	gate := l.clientLogs
	if strings.HasPrefix(msg, "http: Accept error") || strings.HasPrefix(msg, "http: panic serving") ||
		strings.HasPrefix(msg, "http2: panic serving") {
		gate = l.serverLogs
	}
	l.logger.Log(ctx, gate.level(slog.LevelWarn), "HTTP server error", "listener", l.listener, "err", msg)
	return len(p), nil
}
