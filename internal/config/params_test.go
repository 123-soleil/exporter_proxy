package config

import (
	"strings"
	"testing"
)

const probeRoute = `      - path: /probe
        upstream: http://127.0.0.1:9115/probe
        forward_params:
`

func TestForwardParams(t *testing.T) {
	cfg, err := Parse([]byte(withRoutes(probeRoute + `          target:
            values: [https://www.example.com]
            patterns: ['10\.0\.0\.[0-9]{1,3}:443']
            required: true
          module:
            values: [http_2xx]
`)))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Listeners[0].Routes[0].ForwardParams
	target := p["target"]
	if !target.Required || len(target.Values) != 1 || len(target.Patterns) != 1 || p["module"].Required {
		t.Fatalf("ForwardParams = %+v", p)
	}
	// Patterns match whole values.
	for v, want := range map[string]bool{"10.0.0.7:443": true, "x10.0.0.7:443": false, "10.0.0.7:4430": false} {
		if got := target.Patterns[0].MatchString(v); got != want {
			t.Errorf("pattern on %q: %v, want %v", v, got, want)
		}
	}
}

func TestForwardParamsRejected(t *testing.T) {
	tests := []struct{ route, want string }{
		{probeRoute + "          target: {}\n", `forward_params "target": list the allowed values or patterns`},
		{probeRoute + "          target:\n            patterns: ['(']\n", "invalid pattern"},
		{probeRoute + "          \"a&b\":\n            values: [x]\n", "name must only contain"},
		{probeRoute + "          target:\n            values: [\"\"]\n", "values must be non-empty"},
		{"      - path: /probe\n        upstream: http://h/probe?module=x\n        forward_params:\n          module:\n            values: [y]\n", "already set in the upstream URL"},
		{"      - path: /f\n        file: /var/lib/f.prom\n        max_age: 1m\n        forward_params:\n          target:\n            values: [x]\n", "requires an upstream"},
		{"      - path: /probe\n        upstream: http://h/probe\n        forward_params: {}\n", "forward_params is empty"},
		// Closing the anchoring group early would match anything.
		{probeRoute + "          target:\n            patterns: ['10\\.0\\.0\\.1:443)|(.*']\n", "invalid pattern"},
		// A query the proxy could not parse could hide a protected name.
		{"      - path: /probe\n        upstream: http://h/probe?module=a;target=x\n        forward_params:\n          target:\n            values: [y]\n", "upstream URL query cannot be parsed"},
	}
	for _, tt := range tests {
		_, err := Parse([]byte(withRoutes(tt.route)))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("err = %v, want %q", err, tt.want)
		}
	}
}
