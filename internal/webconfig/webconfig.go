// Package webconfig loads exporter-toolkit web configuration files.
//
// Validation stays with exporter-toolkit (web.Validate); Load parses a file
// the same way exporter-toolkit does internally (same defaults, strict YAML,
// same allowed headers, paths relative to the file), so that exporter_proxy can serve TLS and
// basic authentication itself.
package webconfig

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v2"
)

// Load reads and parses the web configuration file at path.
func Load(path string) (*web.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Same defaults as exporter-toolkit.
	c := &web.Config{
		TLSConfig: web.TLSConfig{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		},
		HTTPConfig: web.HTTPConfig{HTTP2: true},
	}
	if err := yaml.UnmarshalStrict(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validateHeaders(c.HTTPConfig.Header); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.TLSConfig.SetDirectory(filepath.Dir(path))
	return c, nil
}

// allowedHeaders lists the headers a web configuration may set, with their
// allowed values (nil: any value). Same list as exporter-toolkit, which
// does not export it: keep in sync when upgrading it.
var allowedHeaders = map[string][]string{
	"Strict-Transport-Security": nil,
	"X-Content-Type-Options":    {"nosniff"},
	"X-Frame-Options":           {"deny", "sameorigin"},
	"X-XSS-Protection":          nil,
	"Content-Security-Policy":   nil,
}

// validateHeaders rejects headers that exporter-toolkit rejects, so that a
// file changed while running is checked like at startup (web.Validate).
func validateHeaders(headers map[string]string) error {
	for k, v := range headers {
		values, ok := allowedHeaders[k]
		if !ok {
			return fmt.Errorf("HTTP header %q can not be configured", k)
		}
		if values != nil && !slices.Contains(values, v) {
			return fmt.Errorf("invalid value for %s. Expected one of: %q, but got: %q", k, values, v)
		}
	}
	return nil
}

// Summary is what exporter_proxy reports about a web configuration.
type Summary struct {
	TLSEnabled bool
	// CertFile, KeyFile and ClientCAFile are resolved against the directory
	// of the web configuration file. Empty when not set (inline PEM or no
	// TLS).
	CertFile     string
	KeyFile      string
	ClientCAFile string
	HasUsers     bool
}

// BasicAuthWithoutTLS reports whether credentials would travel in clear text.
func (s Summary) BasicAuthWithoutTLS() bool { return s.HasUsers && !s.TLSEnabled }

// Read loads the file at path and summarizes it.
func Read(path string) (Summary, error) {
	c, err := Load(path)
	if err != nil {
		return Summary{}, err
	}
	return Summary{
		TLSEnabled:   c.TLSConfig.IsEnabled(),
		CertFile:     c.TLSConfig.TLSCertPath,
		KeyFile:      c.TLSConfig.TLSKeyPath,
		ClientCAFile: c.TLSConfig.ClientCAs,
		HasUsers:     len(c.Users) > 0,
	}, nil
}
