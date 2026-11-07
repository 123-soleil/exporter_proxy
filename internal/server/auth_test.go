package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	config_util "github.com/prometheus/common/config"
	"golang.org/x/crypto/bcrypt"

	"github.com/123-soleil/exporter_proxy/internal/proxy"
	"github.com/123-soleil/exporter_proxy/internal/webconfig"
)

// authRecorder captures AuthFailed events.
type authRecorder struct {
	proxy.NopRecorder
	mu             sync.Mutex
	reasons        []proxy.AuthReason
	webConfigReads []bool
	tlsReads       []bool
}

func (r *authRecorder) AuthFailed(_ string, reason proxy.AuthReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *authRecorder) WebConfigRead(_ string, tls, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.webConfigReads = append(r.webConfigReads, ok)
	if tls {
		r.tlsReads = append(r.tlsReads, ok)
	}
}

func (r *authRecorder) lastTLSRead() (ok, any bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.tlsReads) == 0 {
		return false, false
	}
	return r.tlsReads[len(r.tlsReads)-1], true
}

func (r *authRecorder) reads() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.webConfigReads...)
}

func (r *authRecorder) got() []proxy.AuthReason {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]proxy.AuthReason(nil), r.reasons...)
}

// okHandler counts the requests that passed authentication.
type okHandler struct {
	mu    sync.Mutex
	calls int
}

func (h *okHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.mu.Lock()
	h.calls++
	h.mu.Unlock()
	_, _ = fmt.Fprint(w, "ok")
}

func (h *okHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func newTestAuth(t *testing.T, webContent string, rl webRateLimit) (*authHandler, *okHandler, *authRecorder, *syncBuffer, string) {
	t.Helper()
	path := writeWeb(t, t.TempDir(), "web.yml", webContent)
	next := &okHandler{}
	rec := &authRecorder{}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Like newListener: basic authentication required if the file has users.
	wc, err := webconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := newAuthHandler(authOptions{listener: "node", webConfig: path, rateLimit: rl, requireUsers: len(wc.Users) > 0},
		next, logger, rec)
	return h, next, rec, logs, path
}

func usersYAML(t *testing.T, users map[string]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("basic_auth_users:\n")
	for u, p := range users {
		hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "  %s: %s\n", u, hash)
	}
	return b.String()
}

func do(h http.Handler, user, pass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.0.2.10:40000"
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAuthHandler(t *testing.T) {
	h, next, rec, logs, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})

	tests := []struct {
		name       string
		user, pass string
		wantCode   int
		wantReason proxy.AuthReason
	}{
		{"valid", "prometheus", "good-pass", http.StatusOK, ""},
		{"missing credentials", "", "", http.StatusUnauthorized, proxy.AuthMissingCredentials},
		{"wrong password", "prometheus", "bad-pass", http.StatusUnauthorized, proxy.AuthInvalidCredentials},
		{"unknown user", "intruder", "good-pass", http.StatusUnauthorized, proxy.AuthInvalidCredentials},
		{"valid again (cached)", "prometheus", "good-pass", http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(rec.got())
			w := do(h, tt.user, tt.pass)
			if w.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d", w.Code, tt.wantCode)
			}
			got := rec.got()[before:]
			switch {
			case tt.wantReason == "" && len(got) != 0:
				t.Errorf("unexpected auth failure recorded: %v", got)
			case tt.wantReason != "" && (len(got) != 1 || got[0] != tt.wantReason):
				t.Errorf("recorded %v, want [%s]", got, tt.wantReason)
			}
			if tt.wantCode == http.StatusUnauthorized && !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic") {
				t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}
	if next.count() != 2 {
		t.Errorf("next handler reached %d times, want 2", next.count())
	}
	out := logs.String()
	for _, want := range []string{`reason=invalid_credentials`, `user=intruder`, `remote=192.0.2.10:40000`, `reason=missing_credentials`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"good-pass", "bad-pass"} {
		if strings.Contains(out, secret) {
			t.Errorf("password %q leaked into logs", secret)
		}
	}
}

func TestAuthHandlerNoUsers(t *testing.T) {
	h, next, rec, _, _ := newTestAuth(t, "{}\n", webRateLimit{})
	if w := do(h, "", ""); w.Code != http.StatusOK || next.count() != 1 || len(rec.got()) != 0 {
		t.Errorf("without users: code %d, next %d, failures %v", w.Code, next.count(), rec.got())
	}
}

func TestAuthHandlerHeaders(t *testing.T) {
	h, _, _, _, _ := newTestAuth(t, "http_server_config:\n  headers:\n    X-Frame-Options: deny\n", webRateLimit{})
	if got := do(h, "", "").Header().Get("X-Frame-Options"); got != "deny" {
		t.Errorf("X-Frame-Options = %q, want deny", got)
	}
}

// Wrong passwords are rate limited; scrapers already verified are not.
func TestAuthHandlerVerifyRateLimit(t *testing.T) {
	h, next, rec, logs, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})

	// The legitimate scraper is verified once and cached.
	if w := do(h, "prometheus", "good-pass"); w.Code != http.StatusOK {
		t.Fatalf("first valid request: code %d", w.Code)
	}

	// Brute force: after the burst, attempts get 429 without bcrypt.
	limited := 0
	for i := 0; i < verifyBurst+20; i++ {
		w := do(h, "prometheus", fmt.Sprintf("guess-%d", i))
		if w.Code == http.StatusTooManyRequests {
			limited++
			if w.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
		}
	}
	if limited < 15 {
		t.Errorf("only %d of %d attempts rate limited", limited, verifyBurst+20)
	}

	// The cached scraper is still served during the attack.
	for i := 0; i < 5; i++ {
		if w := do(h, "prometheus", "good-pass"); w.Code != http.StatusOK {
			t.Fatalf("cached valid request during attack: code %d", w.Code)
		}
	}
	if next.count() != 6 {
		t.Errorf("next reached %d times, want 6", next.count())
	}

	rateLimited := 0
	for _, r := range rec.got() {
		if r == proxy.AuthRateLimited {
			rateLimited++
		}
	}
	if rateLimited != limited {
		t.Errorf("recorded %d rate_limited, want %d", rateLimited, limited)
	}
	if !strings.Contains(logs.String(), "level=DEBUG") {
		t.Error("rate limited attempts not logged at debug level")
	}
}

func TestAuthHandlerPasswordChangeInvalidatesCache(t *testing.T) {
	h, _, _, _, path := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "old-pass"}), webRateLimit{})
	if w := do(h, "prometheus", "old-pass"); w.Code != http.StatusOK {
		t.Fatalf("before change: code %d", w.Code)
	}
	mustWriteFile(t, path, usersYAML(t, map[string]string{"prometheus": "new-pass"}))
	if w := do(h, "prometheus", "old-pass"); w.Code != http.StatusUnauthorized {
		t.Errorf("old password after change: code %d, want 401", w.Code)
	}
	if w := do(h, "prometheus", "new-pass"); w.Code != http.StatusOK {
		t.Errorf("new password after change: code %d, want 200", w.Code)
	}
}

// The rate_limit of the web configuration (exporter-toolkit semantics)
// applies to every request.
func TestAuthHandlerWebConfigRateLimit(t *testing.T) {
	h, _, rec, _, _ := newTestAuth(t, "{}\n", webRateLimit{interval: time.Hour, burst: 2})
	codes := []int{do(h, "", "").Code, do(h, "", "").Code, do(h, "", "").Code}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Errorf("codes = %v, want [200 200 429]", codes)
	}
	if got := rec.got(); len(got) != 1 || got[0] != proxy.AuthRateLimited {
		t.Errorf("recorded %v, want [rate_limited]", got)
	}
}

func TestAuthHandlerBrokenWebConfig(t *testing.T) {
	h, next, rec, logs, path := newTestAuth(t, "{}\n", webRateLimit{})
	if w := do(h, "", ""); w.Code != http.StatusOK {
		t.Fatalf("valid web config: code %d", w.Code)
	}
	mustWriteFile(t, path, "not: [valid\n")
	w := do(h, "", "")
	if w.Code != StatusWebConfigUnreadable || next.count() != 1 {
		t.Errorf("broken web config: code %d, next %d, want 518 and 1", w.Code, next.count())
	}
	if got := strings.TrimSpace(w.Body.String()); got != WebConfigUnreadableMessage {
		t.Errorf("body = %q, want %q", got, WebConfigUnreadableMessage)
	}
	if got := rec.reads(); !slices.Equal(got, []bool{true, false}) {
		t.Errorf("web configuration reads recorded %v, want [true false]", got)
	}
	if !strings.Contains(logs.String(), "cannot load web configuration") {
		t.Errorf("error not logged: %s", logs.String())
	}
}

func TestLoggedUserIsTruncated(t *testing.T) {
	h, _, _, logs, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "p"}), webRateLimit{})
	do(h, strings.Repeat("u", 500), "x")
	if strings.Contains(logs.String(), strings.Repeat("u", maxLoggedUserLen+1)) {
		t.Error("long user name not truncated in logs")
	}
}

func TestServerErrorLog(t *testing.T) {
	rec := &authRecorder{}
	logs := &syncBuffer{}
	l := &serverErrorLog{listener: "node", logger: slog.New(slog.NewTextHandler(logs, nil)), rec: rec}

	_, _ = l.Write([]byte("http: TLS handshake error from 192.0.2.1:5555: remote error: tls: bad certificate\n"))
	_, _ = l.Write([]byte("http: Accept error: too many open files; retrying in 5ms\n"))

	if got := rec.got(); len(got) != 1 || got[0] != proxy.AuthTLSHandshake {
		t.Errorf("recorded %v, want [tls_handshake]", got)
	}
	out := logs.String()
	for _, want := range []string{
		`msg="TLS handshake failed"`, "remote=192.0.2.1:5555", `err="remote error: tls: bad certificate"`,
		`msg="HTTP server error"`, "too many open files",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logs lack %q:\n%s", want, out)
		}
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	writeWeb(t, filepath.Dir(path), filepath.Base(path), content)
}

// A brute force from one address does not use up the password checks of
// another client, whose credentials are not cached yet.
func TestAuthHandlerVerifyLimitIsPerClient(t *testing.T) {
	h, _, _, _, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})

	for i := 0; i < clientVerifyBurst+10; i++ {
		do(h, "prometheus", fmt.Sprintf("guess-%d", i)) // from 192.0.2.10
	}
	if w := do(h, "prometheus", "guess-x"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker after its burst: code %d, want 429", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.0.2.20:40000"
	req.SetBasicAuth("prometheus", "good-pass")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("other client during the attack: code %d, want 200", w.Code)
	}
}

func TestClientLimitersEviction(t *testing.T) {
	c := newClientLimiters(1, 1, 2)
	if !c.allow("a") || !c.allow("b") {
		t.Fatal("first tokens refused")
	}
	// Both buckets are empty: the map is full of busy clients and is reset.
	if !c.allow("c") {
		t.Error("new client refused")
	}
	if len(c.m) != 1 {
		t.Errorf("%d limiters kept, want 1", len(c.m))
	}
}

// The rate_limit of the web configuration applies before the file is read.
func TestAuthHandlerRateLimitBeforeReadingWebConfig(t *testing.T) {
	h, _, _, _, path := newTestAuth(t, "{}\n", webRateLimit{interval: time.Hour, burst: 1})
	if w := do(h, "", ""); w.Code != http.StatusOK {
		t.Fatalf("first request: code %d", w.Code)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if w := do(h, "", ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited request: code %d, want 429 without reading the file", w.Code)
	}
}

// When verifications are already pending, new ones get 429 instead of
// queuing behind them.
func TestAuthHandlerPendingVerificationsBounded(t *testing.T) {
	h, next, _, _, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})
	for range maxPendingVerifications {
		h.pending <- struct{}{}
	}
	if w := do(h, "prometheus", "good-pass"); w.Code != http.StatusTooManyRequests {
		t.Errorf("with a full queue: code %d, want 429", w.Code)
	}
	for range maxPendingVerifications {
		<-h.pending
	}
	if w := do(h, "prometheus", "good-pass"); w.Code != http.StatusOK || next.count() != 1 {
		t.Errorf("after the queue drained: code %d, next %d, want 200 and 1", w.Code, next.count())
	}
}

// Unknown users are compared against a hash of the configured cost.
func TestFakeHashForUsesConfiguredCost(t *testing.T) {
	low, _ := bcrypt.GenerateFromPassword([]byte("a"), bcrypt.MinCost)
	high, _ := bcrypt.GenerateFromPassword([]byte("b"), bcrypt.MinCost+2)
	got := fakeHashFor(map[string]config_util.Secret{"a": config_util.Secret(low), "b": config_util.Secret(high)})
	if c, err := bcrypt.Cost(got); err != nil || c != bcrypt.MinCost+2 {
		t.Errorf("fake hash cost = %d (%v), want %d", c, err, bcrypt.MinCost+2)
	}
	if string(fakeHashFor(nil)) != fakeHash {
		t.Error("without configured hashes, the default fake hash is not used")
	}
}

func TestClientKey(t *testing.T) {
	for remote, want := range map[string]string{
		"192.0.2.10:40000":             "192.0.2.10",
		"[::ffff:192.0.2.10]:40000":    "192.0.2.10",
		"[2001:db8:1:2:3:4:5:6]:40000": "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1]:40000": "2001:db8:1:2::/64",
		"[fe80::1%eth0]:40000":         "fe80::/64",
		"@":                            "", // Unix socket: no per-client limit
		"":                             "",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if got := clientKey(r); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", remote, got, want)
		}
	}
}

// A client that leaves while its verification waits gets a refusal, never
// an empty 200, and the refusal is counted.
func TestAuthHandlerClientLeftWhileWaiting(t *testing.T) {
	h, next, rec, _, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx)
	req.RemoteAddr = "192.0.2.10:40000"
	req.SetBasicAuth("prometheus", "wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// The verification is bounded by the pending slots and still answered:
	// never an empty 200.
	if w.Code != http.StatusUnauthorized || next.count() != 0 {
		t.Errorf("code %d, next %d, want 401 and 0", w.Code, next.count())
	}
	if got := rec.got(); !slices.Equal(got, []proxy.AuthReason{proxy.AuthInvalidCredentials}) {
		t.Errorf("recorded %v, want [invalid_credentials]", got)
	}
	if len(h.pending) != 0 {
		t.Errorf("%d verification slots still taken", len(h.pending))
	}
}

// A listener started with basic authentication fails closed when the file
// loses its users (emptied or truncated while being rewritten).
func TestAuthHandlerFailsClosedWhenUsersDisappear(t *testing.T) {
	h, next, rec, logs, path := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})
	for name, content := range map[string]string{
		"empty file":   "",
		"comment only": "# rewritten\n",
		"truncated":    "http_server_config:\n  http2: true\n",
		"no users key": "{}\n",
	} {
		mustWriteFile(t, path, content)
		w := do(h, "", "")
		if w.Code != StatusWebConfigUnreadable {
			t.Errorf("%s: code %d, want 518", name, w.Code)
		}
	}
	if next.count() != 0 {
		t.Errorf("served %d requests without authentication", next.count())
	}
	if got := rec.reads(); slices.Contains(got, true) {
		t.Errorf("reads recorded as successful: %v", got)
	}
	if !strings.Contains(logs.String(), "restart the service to remove authentication") {
		t.Errorf("cause not logged: %s", logs.String())
	}
}

// Identical credentials sent together share one verification.
func TestAuthHandlerSharesConcurrentVerifications(t *testing.T) {
	h, next, rec, _, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "good-pass"}), webRateLimit{})
	h.verifyMu.Lock() // hold verifications until every request is waiting
	const n = 3 * maxPendingVerifications
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = do(h, "prometheus", "good-pass").Code
		}()
	}
	time.Sleep(200 * time.Millisecond)
	h.verifyMu.Unlock()
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("request %d: code %d, want 200", i, c)
		}
	}
	if next.count() != n || len(rec.got()) != 0 {
		t.Errorf("next %d, refusals %v; want %d and none", next.count(), rec.got(), n)
	}
}

// Requests and handshake failures beyond the log rate go to debug level.
func TestAuthHandlerLogsAreRateLimited(t *testing.T) {
	h, _, rec, logs, _ := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "p"}), webRateLimit{})
	const n = logBurst + 20
	for range n {
		do(h, "", "") // missing credentials: no bcrypt, unlimited for an attacker
	}
	if got := len(rec.got()); got != n {
		t.Errorf("counted %d refusals, want %d (all)", got, n)
	}
	warns := strings.Count(logs.String(), "level=WARN")
	if warns < logBurst || warns > logBurst+2 {
		t.Errorf("%d warn lines for %d refusals, want about %d", warns, n, logBurst)
	}
}

// Handshakes refused because of the server's own TLS settings are not
// client authentication failures.
func TestServerErrorLogServerSideTLS(t *testing.T) {
	rec := &authRecorder{}
	logs := &syncBuffer{}
	l := &serverErrorLog{listener: "node", rec: rec, clientLogs: newLogGate(), serverLogs: newLogGate(), trustMarker: true,
		logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}

	_, _ = fmt.Fprintf(l, "http: TLS handshake error from 192.0.2.1:5000: %s: open /etc/cert.pem: permission denied\n", serverTLSUnavailable)
	if got := rec.got(); len(got) != 0 {
		t.Errorf("server-side failure counted as %v", got)
	}
	_, _ = fmt.Fprint(l, "http: TLS handshake error from 192.0.2.1:5001: tls: client didn't provide a certificate\n")
	if got := rec.got(); !slices.Equal(got, []proxy.AuthReason{proxy.AuthTLSHandshake}) {
		t.Errorf("client failure recorded %v, want [tls_handshake]", got)
	}

	// A client cannot hide its failure by putting the marker in text it
	// controls, such as an ALPN protocol name.
	_, _ = fmt.Fprintf(l, "http: TLS handshake error from 192.0.2.1:5002: tls: client requested unsupported application protocols ([%q])\n", serverTLSUnavailable)
	if got := rec.got(); len(got) != 2 {
		t.Errorf("handshake failure with the marker in client text not counted: %v", got)
	}
}

// Users seen while running are required until a reload, even if the
// listener started without them.
func TestAuthHandlerUsersSeenStayRequired(t *testing.T) {
	h, next, _, _, path := newTestAuth(t, "{}\n", webRateLimit{})
	if w := do(h, "", ""); w.Code != http.StatusOK {
		t.Fatalf("without users: code %d", w.Code)
	}
	mustWriteFile(t, path, usersYAML(t, map[string]string{"prometheus": "p"}))
	if w := do(h, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("users added: code %d, want 401", w.Code)
	}
	mustWriteFile(t, path, "")
	if w := do(h, "", ""); w.Code != StatusWebConfigUnreadable || next.count() != 1 {
		t.Errorf("users removed again: code %d, next %d, want 518 and 1", w.Code, next.count())
	}
}

// Client refusals cannot silence the error line of a broken web
// configuration.
func TestAuthHandlerClientNoiseKeepsServerErrors(t *testing.T) {
	h, _, _, logs, path := newTestAuth(t, usersYAML(t, map[string]string{"prometheus": "p"}), webRateLimit{})
	for range 3 * logBurst {
		do(h, "", "") // refusals use up the client log budget
	}
	mustWriteFile(t, path, "not: [valid\n")
	do(h, "", "")
	if !strings.Contains(logs.String(), "level=ERROR msg=\"cannot load web configuration\"") {
		t.Error("web configuration error not logged at error level after client noise")
	}
}

// Server errors that are not handshakes are not hidden by handshake noise.
func TestServerErrorLogKeepsServerErrors(t *testing.T) {
	logs := &syncBuffer{}
	l := &serverErrorLog{listener: "node", rec: &authRecorder{}, clientLogs: newLogGate(), serverLogs: newLogGate(),
		logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	for range 3 * logBurst {
		_, _ = fmt.Fprint(l, "http: TLS handshake error from 192.0.2.1:5000: EOF\n")
	}
	_, _ = fmt.Fprint(l, "http: Accept error: accept tcp: too many open files; retrying in 5ms\n")
	if !strings.Contains(logs.String(), `level=WARN msg="HTTP server error"`) {
		t.Error("accept error not logged at warn after handshake noise")
	}
}

// net/http lines clients can cause (HTTP/2 errors, ...) cannot hide the
// server's own errors.
func TestServerErrorLogClientCausedLines(t *testing.T) {
	logs := &syncBuffer{}
	l := &serverErrorLog{listener: "node", rec: &authRecorder{}, clientLogs: newLogGate(), serverLogs: newLogGate(),
		logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	for range 3 * logBurst {
		_, _ = fmt.Fprint(l, "http2: received GOAWAY [FrameHeader GOAWAY len=8], starting graceful shutdown\n")
	}
	if l.serverLogs.l.Tokens() < logBurst-1 {
		t.Errorf("client-caused lines used the server log budget (%.1f tokens left)", l.serverLogs.l.Tokens())
	}
	_, _ = fmt.Fprint(l, "http: panic serving 192.0.2.1:5000: boom\n")
	if !strings.Contains(logs.String(), "level=WARN msg=\"HTTP server error\" listener=node err=\"http: panic serving") {
		t.Error("panic not logged at warn after client noise")
	}
}

// A plain HTTP listener whose file enables TLS fails closed until a reload,
// instead of serving in clear text what the file wants protected.
func TestAuthHandlerTLSAddedToPlainListener(t *testing.T) {
	h, next, _, _, path := newTestAuth(t, "{}\n", webRateLimit{})
	mustWriteFile(t, path, "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n")
	if w := do(h, "", ""); w.Code != StatusWebConfigUnreadable || next.count() != 0 {
		t.Errorf("code %d, next %d, want 518 and 0", w.Code, next.count())
	}
}

// The server-side marker is only trusted after an IP address: a Unix
// socket client chooses its own path and could put the marker in it.
func TestServerErrorLogMarkerAfterUnixPath(t *testing.T) {
	rec := &authRecorder{}
	l := &serverErrorLog{listener: "node", rec: rec, clientLogs: newLogGate(), serverLogs: newLogGate(),
		logger: slog.New(slog.DiscardHandler)}
	// The client bound its socket to a path imitating "IP:port: marker".
	_, _ = fmt.Fprintf(l, "http: TLS handshake error from 1.2.3.4:5: %s: x: tls: bad certificate\n", serverTLSUnavailable)
	if got := rec.got(); len(got) != 1 {
		t.Errorf("handshake failure from a Unix socket path hidden: %v", got)
	}
}

// HTTP/2 handler panics use the server log budget.
func TestServerErrorLogHTTP2Panic(t *testing.T) {
	l := &serverErrorLog{listener: "node", rec: &authRecorder{}, clientLogs: newLogGate(), serverLogs: newLogGate(),
		logger: slog.New(slog.DiscardHandler)}
	_, _ = fmt.Fprint(l, "http2: panic serving 192.0.2.1:5000: boom\n")
	if got := l.serverLogs.l.Tokens(); got > logBurst-0.5 {
		t.Errorf("HTTP/2 panic not counted in the server log budget (%.1f tokens left)", got)
	}
}
