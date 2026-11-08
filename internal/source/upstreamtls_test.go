package source

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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

// writePEM writes a certificate, and its key when key is not nil.
func writePEM(t *testing.T, dir, name string, der []byte, key *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if key != nil {
		kd, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPath = filepath.Join(dir, name+".key")
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath
}

// clientPKI returns a CA pool and the paths of a client certificate it
// signed.
func clientPKI(t *testing.T, dir string) (*x509.CertPool, string, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "exporter_proxy"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cert, keyPath := writePEM(t, dir, "client", der, key)
	return pool, cert, keyPath
}

func metricsHandler(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, metrics) }

func TestHTTPSUpstream(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(metricsHandler))
	defer srv.Close()
	dir := t.TempDir()
	caPath, _ := writePEM(t, dir, "server-ca", srv.Certificate().Raw, nil)
	route := func(tlsCfg *config.UpstreamTLS) config.Route {
		return config.Route{Upstream: srv.URL + "/metrics", UpstreamTLS: tlsCfg, Limits: limits(2*time.Second, 1<<20)}
	}

	// Verified with the configured CA. httptest certificates are for
	// "example.com" and 127.0.0.1.
	for _, tc := range []*config.UpstreamTLS{{CAFile: caPath}, {CAFile: caPath, ServerName: "example.com"}} {
		res, err := mustNew(t, route(tc)).Fetch(context.Background(), Request{})
		if err != nil || string(res.Body) != metrics {
			t.Errorf("upstream_tls %+v: %v", *tc, err)
		}
	}
	// Without the CA (system roots), or for another name: refused.
	for _, tc := range []*config.UpstreamTLS{nil, {CAFile: caPath, ServerName: "other.example"}} {
		_, err := mustNew(t, route(tc)).Fetch(context.Background(), Request{})
		if ReasonOf(err) != ReasonUnavailable || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("upstream_tls %v: err = %v, want a certificate verification failure", tc, err)
		}
	}
}

func TestHTTPSUpstreamClientCertificate(t *testing.T) {
	dir := t.TempDir()
	pool, cert, key := clientPKI(t, dir)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(metricsHandler))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	caPath, _ := writePEM(t, dir, "server-ca", srv.Certificate().Raw, nil)
	r := config.Route{Upstream: srv.URL + "/metrics", Limits: limits(2*time.Second, 1<<20)}

	r.UpstreamTLS = &config.UpstreamTLS{CAFile: caPath, CertFile: cert, KeyFile: key}
	if _, err := mustNew(t, r).Fetch(context.Background(), Request{}); err != nil {
		t.Errorf("with the client certificate: %v", err)
	}
	r.UpstreamTLS = &config.UpstreamTLS{CAFile: caPath}
	if _, err := mustNew(t, r).Fetch(context.Background(), Request{}); err == nil {
		t.Error("upstream requiring a client certificate answered without one")
	}
}

// Unusable files fail when the source is built (startup or reload), not
// at the first scrape.
func TestHTTPSUpstreamBadFiles(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "x.pem")
	if err := os.WriteFile(notPEM, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		tls  config.UpstreamTLS
		want string
	}{
		{config.UpstreamTLS{CAFile: filepath.Join(dir, "missing.pem")}, "ca_file"},
		{config.UpstreamTLS{CAFile: notPEM}, "no certificate found"},
		{config.UpstreamTLS{CertFile: notPEM, KeyFile: notPEM}, "cert_file and key_file"},
	}
	for _, tt := range tests {
		_, err := New(config.Route{Upstream: "https://127.0.0.1:1/metrics", UpstreamTLS: &tt.tls, Limits: limits(time.Second, 1)})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%+v: err = %v, want %q", tt.tls, err, tt.want)
		}
	}
}
