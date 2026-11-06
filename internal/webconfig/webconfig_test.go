package webconfig

import (
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
		{"users without TLS", "basic_auth_users:\n  u: hash\n", Summary{HasUsers: true}, true},
		{
			"users with TLS files, relative paths",
			"tls_server_config:\n  cert_file: tls/c.crt\n  key_file: /etc/k.key\nbasic_auth_users:\n  u: hash\n",
			Summary{TLSEnabled: true, CertFile: "DIR/tls/c.crt", KeyFile: "/etc/k.key", HasUsers: true},
			false,
		},
		{"users with inline cert", "tls_server_config:\n  cert: x\nbasic_auth_users:\n  u: hash\n", Summary{TLSEnabled: true, HasUsers: true}, false},
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
