package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/123-soleil/exporter_proxy/internal/config"
)

var now = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// writeCert writes a self-signed certificate and its key valid between
// notBefore and notAfter, and returns their paths.
func writeCert(t *testing.T, dir, name string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	writeFile(t, certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	return certPath, keyPath
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tlsWebConfig writes a web configuration using the given certificate,
// key and optional client CA.
func tlsWebConfig(t *testing.T, dir, cert, key, ca string) string {
	t.Helper()
	content := fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n", cert, key)
	if ca != "" {
		content += fmt.Sprintf("  client_ca_file: %s\n  client_auth_type: RequireAndVerifyClientCert\n", ca)
	}
	p := filepath.Join(dir, fmt.Sprintf("web-%d.yml", time.Now().UnixNano()))
	writeFile(t, p, content)
	return p
}

// onlyWebConfig builds a config whose metrics endpoint and single listener
// use the given web configuration and have no file or socket route.
func onlyWebConfig(path string) *config.Config {
	return &config.Config{
		Metrics: config.MetricsEndpoint{WebConfigFile: path},
		Listeners: []config.Listener{{
			Name: "node", WebConfigFile: path,
			Routes: []config.Route{{Path: "/metrics", Upstream: "http://127.0.0.1:1/metrics"}},
		}},
	}
}

func summary(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "[%s] %s: %s\n", f.Severity, f.Where, f.Message)
	}
	return b.String()
}

// want is an expected finding: its severity and a substring of
// "where: message".
type want struct {
	Severity Severity
	Message  string
}

// expect checks that findings contain exactly the wanted severities, with
// each message containing the matching substring.
func expect(t *testing.T, findings []Finding, want ...want) {
	t.Helper()
	if len(findings) != len(want) {
		t.Fatalf("got %d findings, want %d:\n%s", len(findings), len(want), summary(findings))
	}
	for i, w := range want {
		f := findings[i]
		if f.Severity != w.Severity || !strings.Contains(f.Where+": "+f.Message, w.Message) {
			t.Errorf("finding %d = [%s] %s: %s\nwant [%s] containing %q", i, f.Severity, f.Where, f.Message, w.Severity, w.Message)
		}
		if strings.ContainsAny(f.Message, "\r\n") {
			t.Errorf("finding %d spans several lines: %q", i, f.Message)
		}
	}
}

func TestWebConfigs(t *testing.T) {
	dir := t.TempDir()
	day := 24 * time.Hour
	goodCert, goodKey := writeCert(t, dir, "good", now.Add(-day), now.Add(365*day))
	expiredCert, expiredKey := writeCert(t, dir, "expired", now.Add(-365*day), now.Add(-day))
	soonCert, soonKey := writeCert(t, dir, "soon", now.Add(-day), now.Add(10*day))
	futureCert, futureKey := writeCert(t, dir, "future", now.Add(day), now.Add(365*day))
	goodCA, _ := writeCert(t, dir, "ca", now.Add(-day), now.Add(365*day))
	// A rotation bundle: the old, expired CA and the new one.
	rotating := filepath.Join(dir, "rotating-ca.crt")
	expiredPEM, err := os.ReadFile(expiredCert)
	if err != nil {
		t.Fatal(err)
	}
	goodCAPEM, err := os.ReadFile(goodCA)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, rotating, string(expiredPEM)+string(goodCAPEM))
	// An expired certificate written inline.
	expiredKeyPEM, err := os.ReadFile(expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	inlineExpired := filepath.Join(dir, "inline-expired.yml")
	writeFile(t, inlineExpired, "tls_server_config:\n  cert: |\n"+indent(string(expiredPEM))+"  key: |\n"+indent(string(expiredKeyPEM)))
	emptyCA := filepath.Join(dir, "empty-ca.crt")
	writeFile(t, emptyCA, "not a certificate\n")
	basicOnly := filepath.Join(dir, "basic.yml")
	writeFile(t, basicOnly, "basic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n")
	invalid := filepath.Join(dir, "invalid.yml")
	writeFile(t, invalid, "tls_server_config:\n  cert_fil: x\n")

	tests := []struct {
		name string
		web  string
		want []want
	}{
		{"valid TLS and client CA", tlsWebConfig(t, dir, goodCert, goodKey, goodCA), nil},
		{"expired certificate", tlsWebConfig(t, dir, expiredCert, expiredKey, ""),
			[]want{{Problem, `cert_file`}}},
		{"certificate expiring soon", tlsWebConfig(t, dir, soonCert, soonKey, ""),
			[]want{{Warning, `"CN=soon" expires on`}}},
		{"certificate not valid yet", tlsWebConfig(t, dir, futureCert, futureKey, ""),
			[]want{{Problem, "is not valid before"}}},
		{"expired client CA", tlsWebConfig(t, dir, goodCert, goodKey, expiredCert),
			[]want{{Warning, "expired on"}, {Problem, "no currently valid certificate"}}},
		{"client CA bundle rotating", tlsWebConfig(t, dir, goodCert, goodKey, rotating),
			[]want{{Warning, "expired on"}}},
		{"expired inline certificate", inlineExpired,
			[]want{{Problem, "cert (inline)"}}},
		{"client CA without certificate", tlsWebConfig(t, dir, goodCert, goodKey, emptyCA),
			[]want{{Problem, "contains no certificate"}}},
		{"key does not match certificate", tlsWebConfig(t, dir, goodCert, expiredKey, ""),
			[]want{{Problem, "X509KeyPair"}}},
		{"basic auth without TLS", basicOnly,
			[]want{{Warning, "credentials travel in clear text"}}},
		{"unknown key", invalid, []want{{Problem, "cert_fil"}}},
		{"missing file", filepath.Join(dir, "missing.yml"), []want{{Problem, "no such file"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The metrics endpoint and the listener share the file: it is
			// checked only once.
			expect(t, Run(onlyWebConfig(tt.web), now), tt.want...)
		})
	}
}

func TestRoutes(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web.yml")
	writeFile(t, web, "{}\n")

	fresh := filepath.Join(dir, "fresh.prom")
	writeFile(t, fresh, "up 1\n")
	stale := filepath.Join(dir, "stale.prom")
	writeFile(t, stale, "up 1\n")
	future := filepath.Join(dir, "future.prom")
	writeFile(t, future, "up 1\n")
	for path, age := range map[string]time.Duration{fresh: time.Minute, stale: 2 * time.Hour, future: -2 * time.Hour} {
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	sockDir, err := os.MkdirTemp("", "chk") // short path for sockets
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "ok.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	readOnly := filepath.Join(sockDir, "ro.sock")
	ln2, err := net.Listen("unix", readOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln2.Close() }()
	if err := os.Chmod(readOnly, 0o444); err != nil {
		t.Fatal(err)
	}

	fileRoute := func(path string) config.Route {
		return config.Route{Path: "/m", File: path, MaxAge: time.Hour}
	}
	socketRoute := func(path string) config.Route {
		return config.Route{Path: "/m", Upstream: "http://localhost/metrics", UnixSocket: path}
	}

	tests := []struct {
		name  string
		route config.Route
		want  []want
		root  bool // result differs when run as root
	}{
		{name: "fresh file", route: fileRoute(fresh)},
		{name: "stale file", route: fileRoute(stale), want: []want{{Problem, "more than max_age (1h0m0s)"}}},
		{name: "file modified in the future", route: fileRoute(future), want: []want{{Problem, "in the future"}}},
		{name: "missing file", route: fileRoute(filepath.Join(dir, "missing.prom")), want: []want{{Problem, "no such file"}}},
		{name: "directory", route: fileRoute(dir), want: []want{{Problem, "is not a regular file"}}},
		{name: "fifo", route: fileRoute(fifo), want: []want{{Problem, "is not a regular file"}}},
		{name: "socket", route: socketRoute(sock)},
		{name: "missing socket", route: socketRoute(filepath.Join(sockDir, "missing.sock")), want: []want{{Problem, "no such file"}}},
		{name: "socket path is a file", route: socketRoute(fresh), want: []want{{Problem, "is not a socket"}}},
		{name: "read-only socket", route: socketRoute(readOnly), want: []want{{Problem, "is not writable by this user"}}, root: true},
		{name: "TCP upstream not contacted", route: config.Route{Path: "/m", Upstream: "http://127.0.0.1:1/metrics"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.root && os.Geteuid() == 0 {
				t.Skip("root bypasses file permissions")
			}
			cfg := &config.Config{
				Metrics:   config.MetricsEndpoint{WebConfigFile: web},
				Listeners: []config.Listener{{Name: "node", WebConfigFile: web, Routes: []config.Route{tt.route}}},
			}
			findings := Run(cfg, now)
			expect(t, findings, tt.want...)
			for _, f := range findings {
				if !strings.HasPrefix(f.Where, `listener "node" route "/m"`) {
					t.Errorf("finding location = %q", f.Where)
				}
			}
		})
	}
}

func TestReportsEveryProblem(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Metrics: config.MetricsEndpoint{WebConfigFile: filepath.Join(dir, "missing-metrics.yml")},
		Listeners: []config.Listener{{
			Name: "node", WebConfigFile: filepath.Join(dir, "missing-web.yml"),
			Routes: []config.Route{
				{Path: "/a", File: filepath.Join(dir, "a.prom"), MaxAge: time.Hour},
				{Path: "/b", File: filepath.Join(dir, "b.prom"), MaxAge: time.Hour},
			},
		}},
	}
	if got := len(Run(cfg, now)); got != 4 {
		t.Errorf("got %d findings, want 4 (two web configs, two files):\n%s", got, summary(Run(cfg, now)))
	}
}

// For cert_file, only the first certificate (the leaf) is checked, even
// when it cannot be parsed: the next ones are intermediates.
func TestCertificatesLeafOnly(t *testing.T) {
	dir := t.TempDir()
	expiredCert, _ := writeCert(t, dir, "expired", now.Add(-365*24*time.Hour), now.Add(-time.Hour))
	expiredPEM, err := os.ReadFile(expiredCert)
	if err != nil {
		t.Fatal(err)
	}
	brokenLeaf := filepath.Join(dir, "broken-leaf.crt")
	writeFile(t, brokenLeaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))+string(expiredPEM))

	c := &checker{now: now}
	c.certificates("here", "cert_file", brokenLeaf, false)
	expect(t, c.findings, want{Problem, "certificate 1"})

	// A bundle reports every certificate.
	c = &checker{now: now}
	c.certificates("here", "client_ca_file", brokenLeaf, true)
	expect(t, c.findings, want{Warning, "certificate 1"}, want{Warning, "expired on"},
		want{Problem, "no currently valid certificate"})
}

// Unparseable certificates of a bundle are numbered by their position.
func TestCertificateNumbering(t *testing.T) {
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	c := &checker{now: time.Now()}
	c.certificatesPEM("here", "client_ca", []byte(garbage+garbage), true)
	expect(t, c.findings, want{Warning, "certificate 1:"}, want{Warning, "certificate 2:"},
		want{Problem, "no currently valid certificate"})
}

// indent indents every line of s for a YAML block scalar.
func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(s, "\n") {
		if line != "" {
			b.WriteString("    " + line)
		}
	}
	return b.String()
}

// Intermediates of cert_file outside their dates are warnings (clients
// usually skip an expired cross-signature); the leaf stays a problem.
func TestCertFileIntermediateDates(t *testing.T) {
	dir := t.TempDir()
	goodCert, _ := writeCert(t, dir, "leaf", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	expiredCert, _ := writeCert(t, dir, "intermediate", now.Add(-48*time.Hour), now.Add(-time.Hour))
	leafPEM, err := os.ReadFile(goodCert)
	if err != nil {
		t.Fatal(err)
	}
	intPEM, err := os.ReadFile(expiredCert)
	if err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(dir, "chain.crt")
	writeFile(t, chain, string(leafPEM)+string(intPEM))
	c := &checker{now: now}
	c.certificates("here", "cert_file", chain, false)
	expect(t, c.findings, want{Warning, `"CN=intermediate" expired on`})
}
