// Package webconfig reads the few keys of an exporter-toolkit web
// configuration file that exporter_proxy inspects itself: whether TLS is
// enabled, the TLS file paths and whether basic auth users are defined.
//
// Full validation stays with exporter-toolkit (web.Validate); this package
// ignores unknown keys.
package webconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Summary is what exporter_proxy needs to know about a web configuration.
type Summary struct {
	TLSEnabled bool
	// CertFile, KeyFile and ClientCAFile are resolved against the directory
	// of the web configuration file, like exporter-toolkit does. Empty when
	// not set (inline PEM or no TLS).
	CertFile     string
	KeyFile      string
	ClientCAFile string
	HasUsers     bool
}

// BasicAuthWithoutTLS reports whether credentials would travel in clear text.
func (s Summary) BasicAuthWithoutTLS() bool { return s.HasUsers && !s.TLSEnabled }

type file struct {
	TLS struct {
		Cert           string `yaml:"cert"`
		Key            string `yaml:"key"`
		CertFile       string `yaml:"cert_file"`
		KeyFile        string `yaml:"key_file"`
		ClientCA       string `yaml:"client_ca"`
		ClientCAFile   string `yaml:"client_ca_file"`
		ClientAuthType string `yaml:"client_auth_type"`
	} `yaml:"tls_server_config"`
	Users map[string]string `yaml:"basic_auth_users"`
}

// Read parses the web configuration file at path.
func Read(path string) (Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return Summary{}, fmt.Errorf("parse %s: %w", path, err)
	}
	t := f.TLS
	dir := filepath.Dir(path)
	return Summary{
		// Same rule as exporter-toolkit's TLSConfig.IsEnabled.
		TLSEnabled: t.Cert != "" || t.Key != "" || t.CertFile != "" || t.KeyFile != "" ||
			t.ClientCA != "" || t.ClientCAFile != "" || t.ClientAuthType != "",
		CertFile:     resolve(dir, t.CertFile),
		KeyFile:      resolve(dir, t.KeyFile),
		ClientCAFile: resolve(dir, t.ClientCAFile),
		HasUsers:     len(f.Users) > 0,
	}, nil
}

func resolve(dir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}
