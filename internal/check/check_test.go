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

	"golang.org/x/crypto/bcrypt"

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
	mixedCosts := filepath.Join(dir, "mixed-costs.yml")
	low, err := bcrypt.GenerateFromPassword([]byte("p"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, mixedCosts, "basic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n  v: "+string(low)+"\n")
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
		{"bcrypt costs differ", mixedCosts,
			[]want{{Warning, "credentials travel in clear text"}, {Warning, "different bcrypt costs (4 to 10)"}}},
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

// An authorize list that cannot match on its listener is a warning.
func TestAuthorizeWarnings(t *testing.T) {
	web := filepath.Join(t.TempDir(), "web.yml")
	writeFile(t, web, "{}\n") // no users, no TLS
	cfg := onlyWebConfig(web)
	cfg.Listeners[0].Routes[0].Authorize = &config.Authorize{Users: []string{"alice"}, ClientSANs: []string{"app"}}
	expect(t, Run(cfg, now),
		want{Warning, `route "/metrics": authorize users: the web configuration has no basic_auth_users`},
		want{Warning, "authorize client_sans: the web configuration does not verify client certificates"})
}

func TestUpstreamTLSFiles(t *testing.T) {
	dir := t.TempDir()
	day := 24 * time.Hour
	goodCert, goodKey := writeCert(t, dir, "good", now.Add(-day), now.Add(365*day))
	expiredCert, expiredKey := writeCert(t, dir, "expired", now.Add(-365*day), now.Add(-day))
	web := filepath.Join(dir, "web.yml")
	writeFile(t, web, "{}\n")
	run := func(ut *config.UpstreamTLS) []Finding {
		cfg := onlyWebConfig(web)
		cfg.Listeners[0].Routes[0].Upstream = "https://127.0.0.1:1/metrics"
		cfg.Listeners[0].Routes[0].UpstreamTLS = ut
		return Run(cfg, now)
	}
	expect(t, run(&config.UpstreamTLS{CAFile: goodCert, CertFile: goodCert, KeyFile: goodKey}))
	expect(t, run(&config.UpstreamTLS{CertFile: expiredCert, KeyFile: expiredKey}),
		want{Problem, "upstream_tls cert_file"})
	expect(t, run(&config.UpstreamTLS{CertFile: goodCert, KeyFile: expiredKey}),
		want{Problem, "upstream_tls cert_file and key_file"})
	expect(t, run(&config.UpstreamTLS{CAFile: filepath.Join(dir, "missing.pem")}),
		want{Problem, "upstream_tls ca_file"})
}

func TestClientCRLFile(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	crl := func(name string, next time.Time) string {
		d, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: next}, ca, key)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		writeFile(t, p, string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: d})))
		return p
	}
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	srvCert, srvKey := writeCert(t, dir, "server", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	mtls := tlsWebConfig(t, dir, srvCert, srvKey, caPath)
	plain := filepath.Join(dir, "web.yml")
	writeFile(t, plain, "{}\n")
	runWith := func(web, path string) []Finding {
		cfg := onlyWebConfig(web)
		cfg.Metrics.WebConfigFile = mtls
		cfg.Listeners[0].ClientCRLFile = path
		return Run(cfg, now)
	}
	run := func(path string) []Finding { return runWith(mtls, path) }
	expect(t, run(crl("ok.crl", now.Add(30*24*time.Hour))))
	// Refused at startup without verified client certificates: a problem.
	expect(t, runWith(plain, crl("ok2.crl", now.Add(30*24*time.Hour))),
		want{Problem, "client_crl_file needs a web configuration verifying client certificates"})
	expect(t, run(crl("soon.crl", now.Add(3*24*time.Hour))), want{Warning, "must be republished before"})
	expect(t, run(crl("old.crl", now.Add(-time.Minute))), want{Problem, "past its next update"})
	bad := filepath.Join(dir, "bad.crl")
	writeFile(t, bad, "nope")
	expect(t, run(bad), want{Problem, "client_crl_file " + bad})

	// A CRL signed by another CA covers none of the client CAs: every
	// client certificate would be refused at runtime.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherTmpl := *tmpl
	otherTmpl.Subject = pkix.Name{CommonName: "other-ca"}
	otherDER, err := x509.CreateCertificate(rand.Reader, &otherTmpl, &otherTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := x509.ParseCertificate(otherDER)
	otherCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(30 * 24 * time.Hour)}, other, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "foreign.crl")
	writeFile(t, foreign, string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: otherCRL})))
	expect(t, run(foreign), want{Problem, "has no CRL signed by any client CA (CN=ca)"})

	// Two client CAs, a CRL from one of them only: a warning naming the other.
	bundle := filepath.Join(dir, "bundle.pem")
	writeFile(t, bundle, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))+
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER})))
	expect(t, runWith(tlsWebConfig(t, dir, srvCert, srvKey, bundle), crl("one.crl", now.Add(30*24*time.Hour))),
		want{Warning, "has no CRL signed by CN=other-ca"})
}

// TestMain disables the sandbox warnings: tests write their files under
// t.TempDir(), in /tmp. TestSandboxedPaths restores them.
func TestMain(m *testing.M) {
	realSandboxed = sandboxed
	sandboxed = nil
	os.Exit(m.Run())
}

// realSandboxed holds the list disabled by TestMain.
var realSandboxed = sandboxed

func TestSandboxedPaths(t *testing.T) {
	sandboxed = realSandboxed
	t.Cleanup(func() { sandboxed = nil })
	tests := []struct {
		key, path string
		want      string // directive named, "" for no warning
	}{
		{"file", "/tmp/x.prom", "PrivateTmp=yes"},
		{"file", "/var/tmp/x.prom", "PrivateTmp=yes"},
		{"file", "/home/app/x.prom", "ProtectHome=yes"},
		{"unix_socket", "/run/user/1000/app.sock", "ProtectHome=yes"},
		{"file", "/var/lib/batch/x.prom", ""},
		{"file", "/tmpdata/x.prom", ""}, // prefix of a name, not a directory
		{"unix_socket", "/run/app/metrics.sock", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			c := &checker{}
			c.sandbox("route", tt.key, tt.path)
			switch {
			case tt.want == "" && len(c.findings) != 0:
				t.Errorf("unexpected warning: %+v", c.findings)
			case tt.want != "" && (len(c.findings) != 1 || c.findings[0].Severity != Warning ||
				!strings.Contains(c.findings[0].Message, tt.want)):
				t.Errorf("findings = %+v, want one warning naming %s", c.findings, tt.want)
			}
		})
	}
}

func TestExposure(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.yml")
	writeFile(t, open, "{}\n")
	basic := filepath.Join(dir, "basic.yml")
	writeFile(t, basic, "basic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n")

	tests := []struct {
		name       string
		web        string
		listen     string
		restricted bool
		warn       bool
	}{
		{"empty web config on all interfaces", open, ":9100", false, true},
		{"empty web config on a public address", open, "192.0.2.1:9100", false, true},
		{"systemd socket", open, "systemd:node", false, true},
		{"loopback IPv4", open, "127.0.0.1:9100", false, false},
		{"loopback IPv6", open, "[::1]:9100", false, false},
		{"localhost", open, "localhost:9100", false, false},
		{"allowed_networks set", open, ":9100", true, false},
		{"basic auth", basic, ":9100", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &checker{}
			c.exposure("listener", tt.web, tt.listen, tt.restricted)
			if got := len(c.findings) == 1 && c.findings[0].Severity == Warning; got != tt.warn {
				t.Errorf("warning = %v (%+v), want %v", got, c.findings, tt.warn)
			}
		})
	}
}

// TLS alone only encrypts: without required client certificates or basic
// authentication, anyone can read the metrics.
func TestExposureTLSPolicies(t *testing.T) {
	dir := t.TempDir()
	day := 24 * time.Hour
	cert, key := writeCert(t, dir, "srv", now.Add(-day), now.Add(365*day))
	ca, _ := writeCert(t, dir, "ca", now.Add(-day), now.Add(365*day))
	tlsOnly := tlsWebConfig(t, dir, cert, key, "")
	ifGiven := filepath.Join(dir, "ifgiven.yml")
	writeFile(t, ifGiven, fmt.Sprintf("tls_server_config:\n  cert_file: %s\n  key_file: %s\n  client_ca_file: %s\n  client_auth_type: VerifyClientCertIfGiven\n", cert, key, ca))
	mtls := tlsWebConfig(t, dir, cert, key, ca)

	for name, tt := range map[string]struct {
		web  string
		warn bool
	}{
		"TLS without client certificates": {tlsOnly, true},
		"client certificate optional":     {ifGiven, true},
		"client certificate required":     {mtls, false},
	} {
		t.Run(name, func(t *testing.T) {
			c := &checker{}
			c.exposure("listener", tt.web, ":9100", false)
			if got := len(c.findings) == 1; got != tt.warn {
				t.Errorf("warning = %v (%+v), want %v", got, c.findings, tt.warn)
			}
		})
	}
}
