// Package webconfig loads exporter-toolkit web configuration files.
//
// Validation stays with exporter-toolkit (web.Validate); Load parses a file
// the same way exporter-toolkit does internally (same defaults, strict YAML,
// same allowed headers, paths relative to the file), so that exporter_proxy can serve TLS and
// basic authentication itself.
package webconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v2"
	"golang.org/x/crypto/bcrypt"
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
	if err := validateAllowedSANs(&c.TLSConfig); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Paths are relative to the file, like exporter-toolkit: resolved
	// before the checks that read them.
	c.TLSConfig.SetDirectory(filepath.Dir(path))
	if c.TLSConfig.IsEnabled() {
		if err := validateClientCA(&c.TLSConfig); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if err := validateHTTP2Ciphers(c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	// Like exporter-toolkit's validation at startup: a malformed hash would
	// fail instantly and tell its user apart from unknown ones.
	for user, h := range c.Users {
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			return nil, fmt.Errorf("parse %s: basic_auth_users %q: %w", path, user, err)
		}
	}
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

// NormalizeClientAuth resolves exporter-toolkit's names for the same
// client_auth_type.
func NormalizeClientAuth(v string) string {
	switch v {
	case "":
		return "NoClientCert"
	case "RequireClientCert": // exporter-toolkit's old name
		return "RequireAnyClientCert"
	}
	return v
}

// ClientCertPolicy tells what a client_auth_type enforces. The two are
// independent: RequireAnyClientCert requires a certificate without
// verifying it, VerifyClientCertIfGiven verifies one without requiring it.
func ClientCertPolicy(clientAuth string) (required, verified bool) {
	switch NormalizeClientAuth(clientAuth) {
	case "RequireAndVerifyClientCert":
		return true, true
	case "RequireAnyClientCert":
		return true, false
	case "VerifyClientCertIfGiven":
		return false, true
	}
	return false, false // NoClientCert, RequestClientCert
}

// validateAllowedSANs rejects client_allowed_sans that would not restrict
// clients as written: an empty list (exporter-toolkit then refuses every
// certificate, and panics on clients without one), or a list with a
// client_auth_type that does not verify certificates, since any client
// could then present a self-signed certificate carrying an allowed name.
// validateClientCA rejects a client_auth_type that verifies client
// certificates without a client CA: crypto/tls would then verify them
// against the system roots, accepting any client certificate from a CA the
// machine trusts.
//
// The reverse is rejected too: a client CA with a client_auth_type that
// does not verify certificates (RequireAnyClientCert, whose old name
// RequireClientCert reads like "verify") is ignored, and any self-signed
// certificate is accepted. A client CA without any certificate refuses
// every client.
func validateClientCA(tc *web.TLSConfig) error {
	hasCA := tc.ClientCAs != "" || tc.ClientCAsText != ""
	_, verified := ClientCertPolicy(tc.ClientAuth)
	switch {
	case verified && !hasCA:
		return fmt.Errorf("client_auth_type %s verifies client certificates but no client_ca_file or client_ca is set: "+
			"they would be verified against the system roots", NormalizeClientAuth(tc.ClientAuth))
	case !verified && hasCA:
		return fmt.Errorf("client_auth_type %s does not verify client certificates, so the client CA would be ignored: "+
			"use RequireAndVerifyClientCert", NormalizeClientAuth(tc.ClientAuth))
	case !hasCA:
		return nil
	}
	pemData := []byte(tc.ClientCAsText)
	if tc.ClientCAs != "" {
		data, err := os.ReadFile(tc.ClientCAs)
		if err != nil {
			return fmt.Errorf("client_ca_file: %w", err)
		}
		pemData = data
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pemData) {
		return errors.New("the client CA contains no certificate: every client would be refused")
	}
	return nil
}

// http2RequiredCiphers are the cipher suites net/http requires for HTTP/2
// over TLS 1.2 (RFC 7540, section 9.2.2).
var http2RequiredCiphers = []web.Cipher{
	web.Cipher(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
	web.Cipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
}

// validateHTTP2Ciphers rejects a cipher_suites list net/http refuses to
// serve HTTP/2 with: the listener would stop right after starting,
// stopping the whole process.
func validateHTTP2Ciphers(c *web.Config) error {
	tc := c.TLSConfig
	if !c.HTTPConfig.HTTP2 || len(tc.CipherSuites) == 0 || tc.MinVersion >= web.TLSVersion(tls.VersionTLS13) {
		return nil
	}
	for _, required := range http2RequiredCiphers {
		if slices.Contains(tc.CipherSuites, required) {
			return nil
		}
	}
	return errors.New("cipher_suites must include TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or " +
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 when HTTP/2 is enabled and min_version is below TLS13 " +
		"(or set http_server_config.http2: false)")
}

func validateAllowedSANs(tc *web.TLSConfig) error {
	if tc.ClientAllowedSans == nil {
		return nil
	}
	if len(tc.ClientAllowedSans) == 0 {
		return errors.New("client_allowed_sans is empty: remove it or list the allowed names")
	}
	if _, verified := ClientCertPolicy(tc.ClientAuth); !verified {
		return fmt.Errorf("client_allowed_sans needs client_auth_type RequireAndVerifyClientCert or VerifyClientCertIfGiven "+
			"(with %s, certificates are not verified and the names could be forged)", NormalizeClientAuth(tc.ClientAuth))
	}
	return nil
}
