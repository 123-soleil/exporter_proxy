package webconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/prometheus/exporter-toolkit/web"
)

func TestRead(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		want       Summary
		clearCreds bool
	}{
		{"empty", "{}\n", Summary{}, false},
		{"users without TLS", "basic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n", Summary{HasUsers: true, MinBcryptCost: 10, MaxBcryptCost: 10}, true},
		{
			"users with TLS files, relative paths",
			"tls_server_config:\n  cert_file: tls/c.crt\n  key_file: /etc/k.key\nbasic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n",
			Summary{TLSEnabled: true, CertFile: "DIR/tls/c.crt", KeyFile: "/etc/k.key", HasUsers: true, MinBcryptCost: 10, MaxBcryptCost: 10},
			false,
		},
		{"users with inline cert", "tls_server_config:\n  cert: x\nbasic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n", Summary{TLSEnabled: true, CertPEM: "x", HasUsers: true, MinBcryptCost: 10, MaxBcryptCost: 10}, false},
		{
			"mTLS only",
			"tls_server_config:\n  client_ca_file: ca.crt\n  client_auth_type: RequireAndVerifyClientCert\n",
			Summary{TLSEnabled: true, ClientCAFile: "DIR/ca.crt", ClientCertsVerified: true, ClientCertsRequired: true},
			false,
		},
		{"unknown keys ignored", "http_server_config:\n  http2: false\n", Summary{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "web.yml")
			if err := os.WriteFile(p, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			writeTestCA(t, filepath.Join(dir, "ca.crt")) // read by the client CA check
			got, err := Read(p)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			for _, f := range []*string{&want.CertFile, &want.KeyFile, &want.ClientCAFile} {
				if len(*f) > 3 && (*f)[:3] == "DIR" {
					*f = dir + (*f)[3:]
				}
			}
			if got != want {
				t.Errorf("Read = %+v, want %+v", got, want)
			}
			if got.BasicAuthWithoutTLS() != tt.clearCreds {
				t.Errorf("BasicAuthWithoutTLS = %v, want %v", got.BasicAuthWithoutTLS(), tt.clearCreds)
			}
		})
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
		t.Error("Read(missing) succeeded")
	}
}

// Headers are checked like exporter-toolkit does, also when the file
// changes while running.
func TestLoadRejectsHeadersLikeExporterToolkit(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		content string
		wantErr string
	}{
		"allowed":          {"http_server_config:\n  headers:\n    X-Frame-Options: deny\n    Strict-Transport-Security: max-age=31536000\n", ""},
		"forbidden header": {"http_server_config:\n  headers:\n    Set-Cookie: a=b\n", `HTTP header "Set-Cookie" can not be configured`},
		"forbidden value":  {"http_server_config:\n  headers:\n    X-Frame-Options: allow\n", "invalid value for X-Frame-Options"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yml")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			toolkitErr := web.Validate(p)
			if tc.wantErr == "" {
				if err != nil || toolkitErr != nil {
					t.Errorf("Load = %v, web.Validate = %v; want both nil", err, toolkitErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Load error = %v, want %q", err, tc.wantErr)
			}
			if toolkitErr == nil {
				t.Error("exporter-toolkit accepts what Load rejects")
			}
		})
	}
}

// A malformed hash makes the file invalid, like exporter-toolkit at startup.
func TestLoadRejectsInvalidHash(t *testing.T) {
	p := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(p, []byte("basic_auth_users:\n  u: not-a-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), `basic_auth_users "u"`) {
		t.Errorf("Load error = %v, want an invalid hash error naming the user", err)
	}
	if web.Validate(p) == nil {
		t.Error("exporter-toolkit accepts what Load rejects")
	}
}

// client_allowed_sans without a client certificate requested would refuse
// every client: the file is invalid.
func TestLoadRejectsSANsWithoutClientCert(t *testing.T) {
	dir := t.TempDir()
	for name, auth := range map[string]string{
		"unset":                "",
		"NoClientCert":         "  client_auth_type: NoClientCert\n",
		"RequestClientCert":    "  client_auth_type: RequestClientCert\n",
		"RequireAnyClientCert": "  client_auth_type: RequireAnyClientCert\n", // not verified: names could be forged
	} {
		p := filepath.Join(dir, name+".yml")
		content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n" + auth + "  client_allowed_sans:\n    - a\n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "client_allowed_sans needs") {
			t.Errorf("%s: Load error = %v, want client_allowed_sans needs a verifying client_auth_type", name, err)
		}
	}
}

func TestClientCertPolicy(t *testing.T) {
	for v, want := range map[string][2]bool{
		"": {false, false}, "NoClientCert": {false, false}, "RequestClientCert": {false, false},
		"RequireAnyClientCert": {true, false}, "RequireClientCert": {true, false},
		"VerifyClientCertIfGiven":    {false, true},
		"RequireAndVerifyClientCert": {true, true},
	} {
		if req, ver := ClientCertPolicy(v); req != want[0] || ver != want[1] {
			t.Errorf("ClientCertPolicy(%q) = %v, %v; want %v", v, req, ver, want)
		}
	}
}

func TestLoadRejectsEmptyAllowedSANs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "web.yml")
	content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans: []\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "client_allowed_sans is empty") {
		t.Errorf("Load error = %v, want client_allowed_sans is empty", err)
	}
}

// Verifying client certificates without a client CA would trust the system
// roots: the file is invalid.
func TestLoadRejectsVerificationWithoutClientCA(t *testing.T) {
	dir := t.TempDir()
	for _, auth := range []string{"RequireAndVerifyClientCert", "VerifyClientCertIfGiven"} {
		p := filepath.Join(dir, auth+".yml")
		content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: " + auth + "\n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "no client_ca_file or client_ca") {
			t.Errorf("%s: Load error = %v, want missing client CA", auth, err)
		}
	}
}

// writeTestCA writes a PEM certificate (that of an httptest TLS server) to path.
func writeTestCA(t *testing.T, path string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Client CA rules: not ignored, not empty.
func TestLoadClientCARules(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	writeTestCA(t, ca)
	empty := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(empty, []byte("no certificate here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ auth, caFile, wantErr string }{
		"verified":                {"RequireAndVerifyClientCert", ca, ""},
		"CA ignored (RequireAny)": {"RequireAnyClientCert", ca, "would be ignored"},
		"CA ignored (old name)":   {"RequireClientCert", ca, "would be ignored"},
		"CA ignored (Request)":    {"RequestClientCert", ca, "would be ignored"},
		"CA without certificate":  {"RequireAndVerifyClientCert", empty, "contains no certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yml")
			content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: " + tc.auth + "\n  client_ca_file: " + tc.caFile + "\n"
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Load = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Load error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// HTTP/2 needs one of its required cipher suites below TLS 1.3.
func TestLoadRejectsHTTP2WithoutRequiredCipher(t *testing.T) {
	dir := t.TempDir()
	base := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  cipher_suites:\n    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
	for name, tc := range map[string]struct{ extra, wantErr string }{
		"http2 on, TLS 1.2": {"", "cipher_suites must include"},
		"http2 off":         {"http_server_config:\n  http2: false\n", ""},
		"TLS 1.3 only":      {"  min_version: TLS13\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yml")
			content := base + tc.extra
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Load = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Load error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// The client CA check is cached until the file changes.
func TestClientCACheckCachedUntilChange(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	writeTestCA(t, ca)
	p := filepath.Join(dir, "web.yml")
	content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: ca.crt\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("valid CA: %v", err)
	}
	// A changed file (other size or modification time) is checked again.
	if err := os.WriteFile(ca, []byte("no certificate any more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "contains no certificate") {
		t.Errorf("changed CA file not checked again: %v", err)
	}
}

// Requests do not read the client CA: a file briefly missing while being
// rotated fails new TLS connections (Load), not requests on open ones.
func TestLoadForRequestSkipsClientCA(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "web.yml")
	content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: missing.crt\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadForRequest(p); err != nil {
		t.Errorf("LoadForRequest = %v, want nil", err)
	}
	if _, err := Load(p); err == nil {
		t.Error("Load accepted a missing client CA file")
	}
}

// A CA file rewritten keeping its size and modification time is checked
// again (the cache is keyed by content).
func TestClientCACheckSeesSameSizeRewrite(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	writeTestCA(t, ca)
	info, err := os.Stat(ca)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "web.yml")
	content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: ca.crt\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("valid CA: %v", err)
	}
	junk := []byte(strings.Repeat("x", int(info.Size())))
	if err := os.WriteFile(ca, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(ca, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "contains no certificate") {
		t.Errorf("same-size rewrite not checked again: %v", err)
	}
}

func TestLoadRejectsRateLimitWithoutBurst(t *testing.T) {
	p := filepath.Join(t.TempDir(), "web.yml")
	if err := os.WriteFile(p, []byte("rate_limit:\n  interval: 1s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "burst must be at least 1") {
		t.Errorf("Load error = %v, want burst must be at least 1", err)
	}
}

func TestLoadRejectsMinAboveMaxVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "web.yml")
	content := "tls_server_config:\n  cert_file: c.pem\n  key_file: k.pem\n  min_version: TLS13\n  max_version: TLS12\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "min_version is above max_version") {
		t.Errorf("Load error = %v, want min_version is above max_version", err)
	}
}

func TestUnprotected(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		unpro bool
	}{
		{"empty file", "", true},
		{"empty object", "{}\n", true},
		{"basic auth without TLS", "basic_auth_users:\n  u: $2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "web.yml")
			if err := os.WriteFile(p, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := Read(p)
			if err != nil {
				t.Fatal(err)
			}
			if s.Unprotected() != tt.unpro {
				t.Errorf("Unprotected = %v, want %v", s.Unprotected(), tt.unpro)
			}
		})
	}
	// TLS policies: only a required and verified client certificate
	// authenticates.
	for auth, unpro := range map[string]bool{
		"": true, "NoClientCert": true, "RequestClientCert": true, "RequireAnyClientCert": true,
		"VerifyClientCertIfGiven": true, "RequireAndVerifyClientCert": false,
	} {
		s := Summary{TLSEnabled: true, ClientCertsRequired: requiresVerified(auth)}
		if s.Unprotected() != unpro {
			t.Errorf("client_auth_type %q: Unprotected = %v, want %v", auth, s.Unprotected(), unpro)
		}
	}
}

func TestCRLMissing(t *testing.T) {
	now := time.Now()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issue := func(name string, isCA bool, parent *x509.Certificate, parentKey, key *ecdsa.PrivateKey) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	crl := func(issuer *x509.Certificate, key *ecdsa.PrivateKey) *x509.RevocationList {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		l, _ := x509.ParseRevocationList(der)
		return l
	}
	pemOf := func(certs ...*x509.Certificate) []byte {
		var b []byte
		for _, c := range certs {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		return b
	}

	rootKey, interKey, otherKey, leafKey := newKey(), newKey(), newKey(), newKey()
	root := issue("root", true, nil, nil, rootKey)
	inter := issue("intermediate", true, root, rootKey, interKey)
	other := issue("other", true, nil, nil, otherKey)
	pinned := issue("pinned-client", false, nil, nil, leafKey)

	tests := []struct {
		name        string
		bundle      []byte
		lists       []*x509.RevocationList
		wantMissing []string
		wantTotal   int
	}{
		{"root covered", pemOf(root), []*x509.RevocationList{crl(root, rootKey)}, nil, 1},
		{"root not covered", pemOf(root), []*x509.RevocationList{crl(other, otherKey)}, []string{"CN=root"}, 1},
		{"intermediate covered, root above it skipped", pemOf(root, inter), []*x509.RevocationList{crl(inter, interKey)}, nil, 2},
		{"two unrelated CAs, one covered", pemOf(root, other), []*x509.RevocationList{crl(root, rootKey)}, []string{"CN=other"}, 2},
		{"pinned client certificate skipped", pemOf(pinned, root), []*x509.RevocationList{crl(root, rootKey)}, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing, total := CRLMissing(tt.bundle, tt.lists)
			if fmt.Sprint(missing) != fmt.Sprint(tt.wantMissing) || total != tt.wantTotal {
				t.Errorf("CRLMissing = %v, %d; want %v, %d", missing, total, tt.wantMissing, tt.wantTotal)
			}
		})
	}
}
