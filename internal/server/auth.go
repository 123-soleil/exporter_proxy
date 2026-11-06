package server

import (
	"crypto/sha256"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"

	"github.com/123-soleil/exporter_proxy/internal/proxy"
	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// Limits on password verifications that are not already known to succeed.
// bcrypt is deliberately slow (about 250 ms at cost 12): without a limit,
// random passwords would keep a CPU busy and delay legitimate scrapes.
const (
	// verifyRate and verifyBurst bound uncached bcrypt verifications per
	// listener. Scrapers whose credentials were already verified are
	// served from the cache and never limited.
	verifyRate  = 5 // per second
	verifyBurst = 10

	// successCacheSize bounds the cache of verified credentials. Only
	// valid credentials enter it, so an attacker cannot fill or evict it.
	successCacheSize = 1000

	// maxLoggedUserLen truncates user names in logs (client-supplied text).
	maxLoggedUserLen = 64
)

// fakeHash is compared against when the user does not exist, so that
// unknown and known users take the same time (no user enumeration). Same
// value as exporter-toolkit: bcrypt hash of "fakepassword".
const fakeHash = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi"

// authHandler applies the web configuration of a listener to each request,
// like exporter-toolkit does, and reports every refusal:
//
//   - the file is re-read on every request: users, passwords and headers
//     change without restart;
//   - the optional rate_limit of the web configuration applies to all
//     requests (exporter-toolkit semantics);
//   - basic authentication when basic_auth_users is set.
type authHandler struct {
	listener  string
	webConfig string
	next      http.Handler
	logger    *slog.Logger
	rec       proxy.Recorder

	// limiter is the rate_limit of the web configuration, fixed at start
	// like exporter-toolkit; nil when not configured.
	limiter *rate.Limiter
	// verifyLimiter bounds uncached bcrypt verifications.
	verifyLimiter *rate.Limiter
	// verifyMu runs one bcrypt verification at a time, like exporter-toolkit.
	verifyMu  sync.Mutex
	successes *successCache
}

func newAuthHandler(listener, webConfig string, rl webRateLimit, next http.Handler, logger *slog.Logger, rec proxy.Recorder) *authHandler {
	h := &authHandler{
		listener:      listener,
		webConfig:     webConfig,
		next:          next,
		logger:        logger.With("listener", listener),
		rec:           rec,
		verifyLimiter: rate.NewLimiter(verifyRate, verifyBurst),
		successes:     newSuccessCache(successCacheSize),
	}
	if rl.interval > 0 {
		h.limiter = rate.NewLimiter(rate.Every(rl.interval), rl.burst)
	}
	return h
}

// webRateLimit is the rate_limit section of a web configuration.
type webRateLimit struct {
	interval time.Duration
	burst    int
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := webconfig.Load(h.webConfig)
	if err != nil {
		h.logger.Error("cannot load web configuration", "web_config_file", h.webConfig, "err", oneLine(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if h.limiter != nil && !h.limiter.Allow() {
		h.refuse(w, r, proxy.AuthRateLimited, "", http.StatusTooManyRequests)
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
	if !known {
		hash = fakeHash
	}

	// The key covers the stored hash: a password change in the web
	// configuration invalidates the cached success. The password itself is
	// never kept in memory.
	key := sha256.Sum256([]byte(user + "\x00" + string(hash) + "\x00" + pass))
	if known && h.successes.has(key) {
		h.next.ServeHTTP(w, r)
		return
	}

	if !h.verifyLimiter.Allow() {
		h.refuse(w, r, proxy.AuthRateLimited, user, http.StatusTooManyRequests)
		return
	}
	h.verifyMu.Lock()
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
	h.verifyMu.Unlock()

	if !known || err != nil {
		h.refuse(w, r, proxy.AuthInvalidCredentials, user, http.StatusUnauthorized)
		return
	}
	h.successes.add(key)
	h.next.ServeHTTP(w, r)
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
	if reason == proxy.AuthRateLimited {
		// Under attack every attempt is rate limited: keep these at debug
		// level and rely on exporter_proxy_auth_failures_total.
		h.logger.Debug("authentication refused", attrs...)
		w.Header().Set("Retry-After", "1")
	} else {
		h.logger.Warn("authentication refused", attrs...)
	}
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

// serverErrorLog turns net/http server errors into structured log lines and
// counts TLS handshake failures (wrong or missing client certificate, TLS
// version or cipher mismatch, plain HTTP clients, port scanners).
type serverErrorLog struct {
	listener string
	logger   *slog.Logger
	rec      proxy.Recorder
}

const tlsHandshakePrefix = "http: TLS handshake error from "

func (l *serverErrorLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if rest, ok := strings.CutPrefix(msg, tlsHandshakePrefix); ok {
		remote, detail, _ := strings.Cut(rest, ": ")
		l.rec.AuthFailed(l.listener, proxy.AuthTLSHandshake)
		l.logger.Warn("TLS handshake failed", "listener", l.listener, "reason", string(proxy.AuthTLSHandshake),
			"remote", remote, "err", detail)
		return len(p), nil
	}
	l.logger.Warn("HTTP server error", "listener", l.listener, "err", msg)
	return len(p), nil
}
