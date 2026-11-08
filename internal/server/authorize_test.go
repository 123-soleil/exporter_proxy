package server

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// Two users authenticated by the listener; only one may read the route
// restricted to it.
func TestRouteAuthorizeUsers(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", usersYAML(t, map[string]string{"alice": "pw-alice", "bob": "pw-bob"}))
	l := listenerConfig("node", web, up.URL)
	l.Routes = append(l.Routes, config.Route{
		Path: "/app/metrics", Upstream: up.URL + "/metrics", Limits: limits(),
		Authorize: &config.Authorize{Users: []string{"alice"}},
	})
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	base := "http://" + s.Addr("node").String()

	tests := []struct {
		path, user, pass string
		want             int
	}{
		{"/app/metrics", "alice", "pw-alice", http.StatusOK},
		{"/app/metrics", "bob", "pw-bob", http.StatusForbidden},
		{"/app/metrics", "alice", "wrong", http.StatusUnauthorized}, // authentication first
		{"/app/metrics", "", "", http.StatusUnauthorized},
		{"/metrics", "bob", "pw-bob", http.StatusOK}, // other routes unchanged
	}
	for _, tt := range tests {
		if code, _ := get(t, base+tt.path, tt.user, tt.pass); code != tt.want {
			t.Errorf("%s as %q: code %d, want %d", tt.path, tt.user, code, tt.want)
		}
	}
	// A cached success identifies the user too.
	if code, _ := get(t, base+"/app/metrics", "bob", "pw-bob"); code != http.StatusForbidden {
		t.Errorf("bob again (cached): code %d, want 403", code)
	}
}

// An authorize list that cannot match on this listener is reported at
// startup.
func TestRouteAuthorizeWarnings(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n") // no users, no TLS
	l := listenerConfig("node", web, up.URL)
	l.Routes[0].Authorize = &config.Authorize{Users: []string{"alice"}, ClientSANs: []string{"app"}}
	logs := &syncBuffer{}
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, logs)
	for _, want := range []string{"no basic_auth_users", "does not verify client certificates"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("no warning containing %q: %s", want, logs.String())
		}
	}
	// Fail closed: nobody matches.
	if code, _ := get(t, "http://"+s.Addr("node").String()+"/metrics", "", ""); code != http.StatusForbidden {
		t.Errorf("code %d, want 403", code)
	}
}

// Two clients with certificates verified against the client CA; only the
// one whose name is listed may read the restricted route.
func TestRouteAuthorizeClientSANs(t *testing.T) {
	m := newMTLSTest(t, "")
	caA, certA, keyA := testClientPKI(t, t.TempDir(), "scraper-a")
	caB, certB, keyB := testClientPKI(t, t.TempDir(), "scraper-b")
	bundle := filepath.Join(t.TempDir(), "clients-ca.pem")
	var pemData []byte
	for _, p := range []string{caA, caB} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		pemData = append(pemData, data...)
	}
	if err := os.WriteFile(bundle, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	m.writeMTLSWeb(t, bundle)
	m.l.Routes[0].Authorize = &config.Authorize{ClientSANs: []string{"scraper-a"}}
	m.reload(t) // applies mTLS and the authorize list

	a, b := clientWith(t, certA, keyA), clientWith(t, certB, keyB)
	deadline := time.Now().Add(3 * time.Second)
	for tlsGet(a, m.url()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("listed client refused")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tlsGet(b, m.url()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("unlisted client: %v, want code 403", err)
	}
}

// A reload removing a route's authorize (a file cut while being written)
// is refused; changing its list is not.
func TestReloadRemovingAuthorizeRefused(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", usersYAML(t, map[string]string{"alice": "pw"}))
	l := withAddr(t, listenerConfig("node", web, up.URL))
	l.Routes[0].Authorize = &config.Authorize{Users: []string{"alice"}}
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()

	l.Routes[0].Authorize = &config.Authorize{Users: []string{"alice", "bob"}}
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Fatalf("changing the authorize list: %v", err)
	}
	l.Routes[0].Authorize = nil
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err == nil ||
		!strings.Contains(err.Error(), `authorize of route "/metrics"`) {
		t.Errorf("removing authorize: err = %v, want a refusal", err)
	}
	// Removing the route itself is fine: nobody reads it any more.
	l.Routes[0].Path = "/other"
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Errorf("removing the route: %v", err)
	}
}

// A reload removing a route's metrics_filter, or shortening its deny list
// (a file cut while being written), is refused; adding to it is not.
func TestReloadWeakeningMetricsFilterRefused(t *testing.T) {
	var gotAuth atomic.Value
	up := upstream(t, &gotAuth)
	web := writeWeb(t, t.TempDir(), "web.yml", "{}\n")
	l := withAddr(t, listenerConfig("node", web, up.URL))
	deny := func(patterns ...string) *config.MetricsFilter {
		f := &config.MetricsFilter{}
		for _, p := range patterns {
			f.Deny = append(f.Deny, regexp.MustCompile(config.AnchorPattern(p)))
		}
		return f
	}
	l.Routes[0].MetricsFilter = deny("secret_.*", "token_.*")
	s := startServer(t, &config.Config{Listeners: []config.Listener{l}}, io.Discard)
	l.Listen = s.Addr("node").String()
	for name, f := range map[string]*config.MetricsFilter{"removed": nil, "shorter deny list": deny("secret_.*")} {
		l.Routes[0].MetricsFilter = f
		if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err == nil ||
			!strings.Contains(err.Error(), `metrics_filter of route "/metrics"`) {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
	}
	l.Routes[0].MetricsFilter = deny("secret_.*", "token_.*", "key_.*")
	if err := s.Reload(&config.Config{Listeners: []config.Listener{l}}); err != nil {
		t.Errorf("longer deny list: %v", err)
	}
}
