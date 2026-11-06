package main

// End-to-end tests: the whole program (run) with real TLS material generated
// at test time, exercising mTLS, TLS with basic authentication, and what
// reaches the upstream exporter.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// pki is a test certificate authority.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var serial int64

func newSerial() *big.Int {
	serial++
	return big.NewInt(serial)
}

func newCA(t *testing.T, name string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a PEM certificate and key signed by ca.
func (ca *pki) issue(t *testing.T, name string, usage x509.ExtKeyUsage, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// e2e is a running exporter_proxy with an mTLS listener and a TLS + basic
// auth listener in front of the same recording upstream.
type e2e struct {
	dir         string
	ca          *pki
	mtlsURL     string
	basicURL    string
	metricsURL  string
	upstreamReq chan *http.Request
	clientCert  tls.Certificate
	serverCert  string // path of the server certificate
	serverKey   string
}

const e2ePassword = "e2e-s3cret"

func startE2E(t *testing.T) *e2e {
	t.Helper()
	dir := t.TempDir()
	ca := newCA(t, "test-ca")
	e := &e2e{dir: dir, ca: ca, upstreamReq: make(chan *http.Request, 16)}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upstreamReq <- r.Clone(context.Background())
		_, _ = fmt.Fprint(w, "# TYPE up gauge\nup 1\n")
	}))
	t.Cleanup(up.Close)

	// Server certificate, client CA, client certificate.
	e.serverCert, e.serverKey = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	certPEM, keyPEM := ca.issue(t, "server", x509.ExtKeyUsageServerAuth, time.Now().Add(24*time.Hour))
	mustWrite(t, e.serverCert, certPEM)
	mustWrite(t, e.serverKey, keyPEM)
	mustWrite(t, filepath.Join(dir, "ca.crt"), ca.pem)
	clientPEM, clientKey := ca.issue(t, "scraper", x509.ExtKeyUsageClientAuth, time.Now().Add(24*time.Hour))
	cc, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	e.clientCert = cc

	hash, err := bcrypt.GenerateFromPassword([]byte(e2ePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// Relative paths: resolved against the web configuration directory.
	mustWrite(t, filepath.Join(dir, "web-mtls.yml"), []byte(`tls_server_config:
  cert_file: server.crt
  key_file: server.key
  client_ca_file: ca.crt
  client_auth_type: RequireAndVerifyClientCert
`))
	mustWrite(t, filepath.Join(dir, "web-basic.yml"), []byte(fmt.Sprintf(`tls_server_config:
  cert_file: server.crt
  key_file: server.key
basic_auth_users:
  prometheus: %s
`, hash)))

	mtlsPort, basicPort, metricsPort := freePort(t), freePort(t), freePort(t)
	cfg := filepath.Join(dir, "config.yml")
	mustWrite(t, cfg, []byte(fmt.Sprintf(`
metrics:
  listen: "127.0.0.1:%d"
  web_config_file: %s
listeners:
  - name: mtls
    listen: "127.0.0.1:%d"
    web_config_file: %s
    routes:
      - path: /metrics
        upstream: %s/metrics
  - name: basic
    listen: "127.0.0.1:%d"
    web_config_file: %s
    routes:
      - path: /metrics
        upstream: %s/metrics
`, metricsPort, filepath.Join(dir, "web-mtls.yml"),
		mtlsPort, filepath.Join(dir, "web-mtls.yml"), up.URL,
		basicPort, filepath.Join(dir, "web-basic.yml"), up.URL)))

	e.mtlsURL = fmt.Sprintf("https://127.0.0.1:%d/metrics", mtlsPort)
	e.basicURL = fmt.Sprintf("https://127.0.0.1:%d/metrics", basicPort)
	e.metricsURL = fmt.Sprintf("https://127.0.0.1:%d/metrics", metricsPort)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	logs := &lockedBuffer{}
	go func() { done <- run(ctx, []string{"--config=" + cfg}, io.Discard, logs) }()
	t.Cleanup(func() {
		cancel()
		if code := <-done; code != exitOK {
			t.Errorf("exit code = %d, want 0\n%s", code, logs.String())
		}
	})

	// Wait until the mTLS listener answers.
	client := e.client(t, &e.clientCert, 0)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(e.mtlsURL)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy not ready: %v\n%s", err, logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Drain the readiness request.
	for len(e.upstreamReq) > 0 {
		<-e.upstreamReq
	}
	return e
}

// client returns an HTTPS client trusting the test CA, presenting cert if
// not nil, with an optional maximum TLS version.
func (e *e2e) client(t *testing.T, cert *tls.Certificate, maxVersion uint16) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.cert)
	cfg := &tls.Config{RootCAs: roots, MaxVersion: maxVersion}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true},
	}
}

func TestE2EMutualTLS(t *testing.T) {
	e := startE2E(t)

	otherCA := newCA(t, "other-ca")
	otherPEM, otherKey := otherCA.issue(t, "intruder", x509.ExtKeyUsageClientAuth, time.Now().Add(24*time.Hour))
	other, err := tls.X509KeyPair(otherPEM, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredPEM, expiredKey := e.ca.issue(t, "expired", x509.ExtKeyUsageClientAuth, time.Now().Add(-time.Hour))
	expired, err := tls.X509KeyPair(expiredPEM, expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	serverOnlyPEM, serverOnlyKey := e.ca.issue(t, "not-a-client", x509.ExtKeyUsageServerAuth, time.Now().Add(24*time.Hour))
	serverOnly, err := tls.X509KeyPair(serverOnlyPEM, serverOnlyKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		cert       *tls.Certificate
		maxVersion uint16
		wantOK     bool
	}{
		{"valid client certificate", &e.clientCert, 0, true},
		{"no client certificate", nil, 0, false},
		{"certificate from another CA", &other, 0, false},
		{"expired client certificate", &expired, 0, false},
		{"certificate without client usage", &serverOnly, 0, false},
		{"TLS 1.1 refused", &e.clientCert, tls.VersionTLS11, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := e.client(t, tt.cert, tt.maxVersion).Get(e.mtlsURL)
			if !tt.wantOK {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatalf("request succeeded with code %d, want a TLS failure", resp.StatusCode)
				}
				if !strings.Contains(strings.ToLower(err.Error()), "tls") {
					t.Errorf("failure is not a TLS error: %v", err)
				}
				select {
				case <-e.upstreamReq:
					t.Error("upstream reached despite the TLS failure")
				default:
				}
				return
			}
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "up 1") {
				t.Errorf("code %d body %q", resp.StatusCode, body)
			}
			<-e.upstreamReq
		})
	}
}

func TestE2EBasicAuthOverTLS(t *testing.T) {
	e := startE2E(t)
	client := e.client(t, nil, 0)

	tests := []struct {
		name     string
		user     string
		password string
		want     int
	}{
		{"valid credentials", "prometheus", e2ePassword, http.StatusOK},
		{"wrong password", "prometheus", "nope", http.StatusUnauthorized},
		{"no credentials", "", "", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, e.basicURL+"?collect=x", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.user != "" {
				req.SetBasicAuth(tt.user, tt.password)
			}
			req.Header.Set("X-Forwarded-For", "10.0.0.1")
			req.Header.Set("Cookie", "session=abc")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("code %d, want %d", resp.StatusCode, tt.want)
			}
			if tt.want != http.StatusOK {
				select {
				case <-e.upstreamReq:
					t.Error("upstream reached without valid credentials")
				default:
				}
				return
			}

			// What reached the upstream: no credentials, no client headers,
			// no client query string.
			up := <-e.upstreamReq
			for _, h := range []string{"Authorization", "X-Forwarded-For", "Cookie"} {
				if v := up.Header.Get(h); v != "" {
					t.Errorf("client header %s forwarded upstream: %q", h, v)
				}
			}
			if up.URL.RawQuery != "" {
				t.Errorf("client query string forwarded upstream: %q", up.URL.RawQuery)
			}
		})
	}
}

func TestE2EPlainHTTPToTLSListener(t *testing.T) {
	e := startE2E(t)
	resp, err := http.Get(strings.Replace(e.basicURL, "https://", "http://", 1))
	if err != nil {
		return // connection refused or reset: also acceptable
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("plain HTTP on a TLS listener: code %d, want 400", resp.StatusCode)
	}
}

func TestE2EMetricsEndpointUsesItsWebConfig(t *testing.T) {
	e := startE2E(t)
	if resp, err := e.client(t, nil, 0).Get(e.metricsURL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("metrics endpoint answered without a client certificate")
	}
	resp, err := e.client(t, &e.clientCert, 0).Get(e.metricsURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "exporter_proxy_build_info") {
		t.Errorf("metrics endpoint body lacks build_info")
	}
}

// A renewed server certificate is used for new connections, without reload
// or restart.
func TestE2ECertificateRotation(t *testing.T) {
	e := startE2E(t)

	serial := func() *big.Int {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(e.ca.cert)
		conn, err := tls.Dial("tcp", strings.TrimSuffix(strings.TrimPrefix(e.mtlsURL, "https://"), "/metrics"),
			&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{e.clientCert}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber
	}

	before := serial()
	certPEM, keyPEM := e.ca.issue(t, "server-renewed", x509.ExtKeyUsageServerAuth, time.Now().Add(48*time.Hour))
	// Between the two writes a new connection would see a mismatched pair
	// and fail; no connection is made here until both files are written.
	mustWrite(t, e.serverKey, keyPEM)
	mustWrite(t, e.serverCert, certPEM)

	if after := serial(); after.Cmp(before) == 0 {
		t.Errorf("server certificate not renewed for new connections (serial %v)", after)
	}
}
