package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// withNetworks returns a configuration whose listener has the given
// allowed_networks block (items indented by six spaces), or an empty list
// written inline when block is "[]".
func withNetworks(block string) string {
	sep := "\n"
	if block == "[]" {
		sep = " "
	}
	return withListeners(`  - name: a
    listen: ":9100"
    web_config_file: /etc/ep/web.yml
    allowed_networks:` + sep + block + `
    routes:
` + okRoute)
}

func TestAllowedNetworks(t *testing.T) {
	cfg, err := Parse([]byte(withNetworks("      - 10.0.0.0/8\n      - 192.0.2.10\n      - 2001:db8::/32\n      - \"::ffff:198.51.100.0/120\"")))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.10/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("198.51.100.0/24"), // IPv4-mapped form unmapped
	}
	if got := cfg.Listeners[0].AllowedNetworks; !slices.Equal(got, want) {
		t.Errorf("AllowedNetworks = %v, want %v", got, want)
	}

	// Unset: every address.
	cfg, err = Parse([]byte(withRoutes(okRoute)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listeners[0].AllowedNetworks != nil || cfg.Metrics.AllowedNetworks != nil {
		t.Error("allowed_networks set although absent from the file")
	}
}

func TestAllowedNetworksOnMetrics(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(withRoutes(okRoute),
		"web_config_file: /etc/ep/web-metrics.yml\n",
		"web_config_file: /etc/ep/web-metrics.yml\n  allowed_networks: [127.0.0.1]\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Metrics.AllowedNetworks; len(got) != 1 || got[0] != netip.MustParsePrefix("127.0.0.1/32") {
		t.Errorf("metrics AllowedNetworks = %v", got)
	}
}

func TestAllowedNetworksRejected(t *testing.T) {
	tests := []struct {
		name, block, want string
	}{
		{"empty list", "[]", "allowed_networks is empty"},
		{"host bits set", "      - 10.1.2.3/8", `host bits set, use "10.0.0.0/8"`},
		{"not an address", "      - example.com", `allowed_networks "example.com"`},
		{"bad prefix length", "      - 10.0.0.0/33", `allowed_networks "10.0.0.0/33"`},
		{"zone", "      - fe80::1%eth0", "zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(withNetworks(tt.block)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
