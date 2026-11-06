// Package webconfig loads exporter-toolkit web configuration files.
//
// Validation stays with exporter-toolkit (web.Validate); Load parses a file
// the same way exporter-toolkit does internally (same defaults, strict YAML,
// paths relative to the file), so that exporter_proxy can serve TLS and
// basic authentication itself.
package webconfig

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

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
	c.TLSConfig.SetDirectory(filepath.Dir(path))
	return c, nil
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
