package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/123-soleil/exporter_proxy/internal/proxy"
)

// authRecorder captures AuthFailed events.
type authRecorder struct {
	proxy.NopRecorder
	mu      sync.Mutex
	reasons []proxy.AuthReason
}

func (r *authRecorder) AuthFailed(_ string, reason proxy.AuthReason) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
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
	return newAuthHandler("node", path, rl, next, logger, rec), next, rec, logs, path
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
	h, next, _, logs, path := newTestAuth(t, "{}\n", webRateLimit{})
	mustWriteFile(t, path, "not: [valid\n")
	if w := do(h, "", ""); w.Code != http.StatusInternalServerError || next.count() != 0 {
		t.Errorf("broken web config: code %d, next %d, want 500 and 0", w.Code, next.count())
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
