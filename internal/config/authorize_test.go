package config

import (
	"slices"
	"strings"
	"testing"
)

func TestAuthorize(t *testing.T) {
	cfg, err := Parse([]byte(withRoutes(okRoute + `      - path: /app/metrics
        upstream: http://127.0.0.1:9000/metrics
        authorize:
          users: [app-team]
          client_sans: [app.example.com, "spiffe://example.com/app"]
`)))
	if err != nil {
		t.Fatal(err)
	}
	routes := cfg.Listeners[0].Routes
	if routes[0].Authorize != nil {
		t.Error("route without authorize got one")
	}
	a := routes[1].Authorize
	if a == nil || !slices.Equal(a.Users, []string{"app-team"}) ||
		!slices.Equal(a.ClientSANs, []string{"app.example.com", "spiffe://example.com/app"}) {
		t.Errorf("Authorize = %+v", a)
	}
}

func TestAuthorizeRejected(t *testing.T) {
	tests := []struct {
		name, block, want string
	}{
		{"empty", "        authorize: {}\n", "authorize must list users or client_sans"},
		{"empty lists", "        authorize:\n          users: []\n", "authorize must list users or client_sans"},
		{"empty name", "        authorize:\n          users: [\"\"]\n", "authorize users: empty name"},
		{"duplicate", "        authorize:\n          client_sans: [a, a]\n", `authorize client_sans: duplicate "a"`},
		{"unknown key", "        authorize:\n          user: [a]\n", "user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(withRoutes(okRoute + tt.block)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
