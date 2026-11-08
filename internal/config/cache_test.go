package config

import (
	"strings"
	"testing"
	"time"
)

func TestCacheTTL(t *testing.T) {
	cfg, err := Parse([]byte(withRoutes("      - path: /m\n        upstream: http://h/m\n        cache_ttl: 30s\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listeners[0].Routes[0].CacheTTL; got != 30*time.Second {
		t.Errorf("CacheTTL = %s", got)
	}
	tests := []struct{ route, want string }{
		{"      - path: /m\n        upstream: http://h/m\n        cache_ttl: 2h\n", "cache_ttl must be at most 1h0m0s"},
		{"      - path: /m\n        upstream: http://h/m\n        cache_ttl: 0s\n", "cache_ttl must be greater than 0"},
		{"      - path: /m\n        file: /var/lib/m.prom\n        max_age: 1m\n        cache_ttl: 30s\n", "cache_ttl requires an upstream"},
		{"      - path: /m\n        upstream: http://h/m\n        cache_ttl: 30s\n        forward_params:\n          target:\n            values: [x]\n", "mutually exclusive"},
	}
	for _, tt := range tests {
		_, err := Parse([]byte(withRoutes(tt.route)))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("err = %v, want %q", err, tt.want)
		}
	}
}

func TestRouteMaxConcurrentRequests(t *testing.T) {
	cfg, err := Parse([]byte(withRoutes("      - path: /m\n        upstream: http://h/m\n        max_concurrent_requests: 1\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listeners[0].Routes[0].MaxConcurrentRequests; got != 1 {
		t.Errorf("MaxConcurrentRequests = %d", got)
	}
	for route, want := range map[string]string{
		"      - path: /m\n        upstream: http://h/m\n        max_concurrent_requests: 0\n": "max_concurrent_requests must be greater than 0",
		"      - path: /m\n        upstream: http://h/m\n        max_concurrent_requests: 3\n": "is above the listener's (2)",
	} {
		if _, err := Parse([]byte(withRoutes(route))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}
}
