package config

import (
	"strings"
	"testing"
)

// withSD returns a valid configuration whose metrics section has the given
// service_discovery block (indented by four spaces).
func withSD(block string) string {
	return strings.Replace(withRoutes(okRoute), "web_config_file: /etc/ep/web-metrics.yml\n",
		"web_config_file: /etc/ep/web-metrics.yml\n  service_discovery:\n"+block, 1)
}

func TestServiceDiscovery(t *testing.T) {
	cfg, err := Parse([]byte(withSD("    host: node1.example.com\n    labels:\n      dc: par1\n")))
	if err != nil {
		t.Fatal(err)
	}
	sd := cfg.Metrics.ServiceDiscovery
	if sd == nil || sd.Host != "node1.example.com" || sd.Labels["dc"] != "par1" {
		t.Errorf("ServiceDiscovery = %+v", sd)
	}
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "node1"} {
		if _, err := Parse([]byte(withSD("    host: \"" + host + "\"\n"))); err != nil {
			t.Errorf("host %q: %v", host, err)
		}
	}
	cfg, err = Parse([]byte(withRoutes(okRoute)))
	if err != nil || cfg.Metrics.ServiceDiscovery != nil {
		t.Errorf("service discovery enabled without the block (err %v)", err)
	}
}

func TestServiceDiscoveryRejected(t *testing.T) {
	tests := []struct{ block, want string }{
		{"    labels: {dc: x}\n", "host is required"},
		{"    host: node1:9100\n", "without scheme, port or brackets"},
		{"    host: https://node1\n", "without scheme, port or brackets"},
		{"    host: \"[2001:db8::1]\"\n", "without scheme, port or brackets"},
		{"    host: \"2001:db8::zz\"\n", "not a valid IPv6 address"},
		{"    host: n\n    labels: {\"1dc\": x}\n", "not a valid Prometheus label name"},
		{"    host: n\n    labels: {__scheme__: http}\n", "reserved"},
		{"    host: n\n    labels: {exporter_proxy_route: x}\n", "set by exporter_proxy"},
	}
	for _, tt := range tests {
		_, err := Parse([]byte(withSD(tt.block)))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: err = %v, want %q", tt.block, err, tt.want)
		}
	}
}
