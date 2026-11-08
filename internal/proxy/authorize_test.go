package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/123-soleil/exporter_proxy/internal/config"
	"github.com/123-soleil/exporter_proxy/internal/source"
)

// tlsState returns a connection state with a client certificate carrying
// the given names, verified or not.
func tlsState(verified bool) *tls.ConnectionState {
	u, _ := url.Parse("spiffe://example.com/app")
	leaf := &x509.Certificate{
		DNSNames:       []string{"App.Example.com"},
		EmailAddresses: []string{"ops@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.7")},
		URIs:           []*url.URL{u},
	}
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if verified {
		cs.VerifiedChains = [][]*x509.Certificate{{leaf}}
	}
	return cs
}

func TestAuthorizationAllows(t *testing.T) {
	z := newAuthorization(&config.Authorize{
		Users:      []string{"alice"},
		ClientSANs: []string{"app.example.com", "192.0.2.7", "spiffe://example.com/app", "ops@example.com"},
	})
	tests := []struct {
		name string
		user string // "" for none
		tls  *tls.ConnectionState
		want bool
	}{
		{"listed user", "alice", nil, true},
		{"other user", "bob", nil, false},
		{"no identity", "", nil, false},
		{"verified certificate with a listed name", "", tlsState(true), true},
		{"unverified certificate (self-signed under RequireAnyClientCert)", "", tlsState(false), false},
		{"other user, listed certificate", "bob", tlsState(true), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/m", nil)
			if tt.user != "" {
				req = req.WithContext(WithUser(req.Context(), tt.user))
			}
			req.TLS = tt.tls
			if got, _ := z.allows(req); got != tt.want {
				t.Errorf("allows = %v, want %v", got, tt.want)
			}
		})
	}

	// Each kind of name matches on its own.
	for _, san := range []string{"app.example.com", "192.0.2.7", "spiffe://example.com/app", "ops@example.com"} {
		z := newAuthorization(&config.Authorize{ClientSANs: []string{san}})
		req := httptest.NewRequest(http.MethodGet, "/m", nil)
		req.TLS = tlsState(true)
		if ok, who := z.allows(req); !ok {
			t.Errorf("client_sans %q: refused (who %q)", san, who)
		}
	}
}

// DNS names compare without case; URIs and email addresses exactly.
func TestAuthorizationNameCase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/m", nil)
	req.TLS = tlsState(true) // DNS App.Example.com, spiffe://example.com/app, ops@example.com
	for san, want := range map[string]bool{
		"app.example.com":          true,
		"APP.EXAMPLE.COM":          true,
		"SPIFFE://example.com/APP": false,
		"OPS@example.com":          false,
	} {
		z := newAuthorization(&config.Authorize{ClientSANs: []string{san}})
		if got, _ := z.allows(req); got != want {
			t.Errorf("client_sans %q: allowed %v, want %v", san, got, want)
		}
	}
}

// A DNS name spelled like an IP address does not match an IP entry.
func TestAuthorizationDNSNameLikeIP(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"192.0.2.7"}}
	req := httptest.NewRequest(http.MethodGet, "/m", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	z := newAuthorization(&config.Authorize{ClientSANs: []string{"192.0.2.7"}})
	if ok, _ := z.allows(req); ok {
		t.Error("DNS name matched an IP address entry")
	}
}

// A basic auth header the authentication layer did not verify (listener
// without basic_auth_users) does not identify a user.
func TestAuthorizationIgnoresUnverifiedBasicAuth(t *testing.T) {
	z := newAuthorization(&config.Authorize{Users: []string{"alice"}})
	req := httptest.NewRequest(http.MethodGet, "/m", nil)
	req.SetBasicAuth("alice", "anything")
	if ok, _ := z.allows(req); ok {
		t.Error("unverified basic auth header allowed")
	}
}

func TestHandlerAuthorize(t *testing.T) {
	src := fakeSource{res: &source.Result{Body: []byte(metrics)}}
	h := newHandler("test", []route{
		{path: "/open", src: src, maxSamples: 100},
		{path: "/app", src: src, maxSamples: 100, authz: newAuthorization(&config.Authorize{Users: []string{"alice"}})},
	}, 2, Options{})
	do := func(path, user string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if user != "" {
			req = req.WithContext(WithUser(req.Context(), user))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := do("/app", "alice"); c != http.StatusOK {
		t.Errorf("alice on /app: %d, want 200", c)
	}
	if c := do("/app", "bob"); c != http.StatusForbidden {
		t.Errorf("bob on /app: %d, want 403", c)
	}
	if c := do("/open", "bob"); c != http.StatusOK {
		t.Errorf("bob on /open: %d, want 200", c)
	}
}
