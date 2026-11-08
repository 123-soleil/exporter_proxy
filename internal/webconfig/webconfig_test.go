package webconfig

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
			Summary{TLSEnabled: true, ClientCAFile: "DIR/ca.crt"},
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
