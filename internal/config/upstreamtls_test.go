package config

import (
	"strings"
	"testing"
)

func TestUpstreamTLS(t *testing.T) {
	cfg, err := Parse([]byte(withRoutes(`      - path: /m
        upstream: https://exporter.internal:9100/metrics
        upstream_tls:
          ca_file: /etc/ep/ca.pem
          cert_file: /etc/ep/client.crt
          key_file: /etc/ep/client.key
          server_name: exporter.internal
      - path: /system-roots
        upstream: https://exporter.example.com/metrics
`)))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Listeners[0].Routes[0].UpstreamTLS
	want := UpstreamTLS{CAFile: "/etc/ep/ca.pem", CertFile: "/etc/ep/client.crt", KeyFile: "/etc/ep/client.key", ServerName: "exporter.internal"}
	if got == nil || *got != want {
		t.Errorf("UpstreamTLS = %+v, want %+v", got, want)
	}
	if cfg.Listeners[0].Routes[1].UpstreamTLS != nil {
		t.Error("UpstreamTLS set although absent")
	}
}

func TestUpstreamTLSRejected(t *testing.T) {
	tests := []struct {
		name, route, want string
	}{
		{"on http", "        upstream: http://h/m\n        upstream_tls:\n          ca_file: /ca.pem\n", "upstream_tls requires an https:// upstream"},
		{"cert without key", "        upstream: https://h/m\n        upstream_tls:\n          cert_file: /c.crt\n", "cert_file and key_file go together"},
		{"relative path", "        upstream: https://h/m\n        upstream_tls:\n          ca_file: ca.pem\n", "upstream_tls ca_file must be an absolute path"},
		{"empty", "        upstream: https://h/m\n        upstream_tls: {}\n", "upstream_tls is empty"},
		{"unix socket", "        upstream: https://h/m\n        unix_socket: /run/s.sock\n", "unix_socket requires an http:// upstream"},
		{"insecure option", "        upstream: https://h/m\n        upstream_tls:\n          insecure_skip_verify: true\n", "insecure_skip_verify"},
		{"other scheme", "        upstream: ftp://h/m\n", "http:// or https://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(withRoutes("      - path: /m\n" + tt.route)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
