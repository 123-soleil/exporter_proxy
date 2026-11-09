// Package webconfig loads exporter-toolkit web configuration files.
//
// Validation stays with exporter-toolkit (web.Validate); Load parses a file
// the same way exporter-toolkit does internally (same defaults, strict YAML,
// same allowed headers, paths relative to the file), so that exporter_proxy can serve TLS and
// basic authentication itself.
package webconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/prometheus/exporter-toolkit/web"
	"go.yaml.in/yaml/v2"
	"golang.org/x/crypto/bcrypt"
)

// Load reads and parses the web configuration file at path.
func Load(path string) (*web.Config, error) { return load(path, true) }

// LoadForRequest is Load without reading the client CA: requests on
// connections already open do not use it (it is checked on every new TLS
// connection), so a client CA file briefly missing while being rotated does
// not fail them.
func LoadForRequest(path string) (*web.Config, error) { return load(path, false) }

func load(path string, checkCA bool) (*web.Config, error) {
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
	// A rate_limit interval with no burst would refuse every request.
	if rl := c.RateLimiterConfig; rl.Interval > 0 && rl.Burst < 1 {
		return nil, fmt.Errorf("parse %s: rate_limit: burst must be at least 1 when interval is set", path)
	}
	// Paths are relative to the file, like exporter-toolkit: resolved
	// before the checks that read them.
	c.TLSConfig.SetDirectory(filepath.Dir(path))
	if c.TLSConfig.IsEnabled() {
		if c.TLSConfig.MinVersion > c.TLSConfig.MaxVersion {
			return nil, fmt.Errorf("parse %s: min_version is above max_version: no TLS version left", path)
		}
		if err := validateClientCA(&c.TLSConfig, checkCA); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if err := ValidateHTTP2Ciphers(c); err != nil {
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
	// CertPEM and ClientCAPEM are the inline certificates (cert, client_ca).
	CertPEM     string
	ClientCAPEM string
	HasUsers    bool
	// ClientCertsRequired: TLS with a client_auth_type that requires and
	// verifies a client certificate (RequireAndVerifyClientCert).
	ClientCertsRequired bool
	// ClientCertsVerified: TLS with a client_auth_type that verifies
	// client certificates against the client CA.
	ClientCertsVerified bool
	// MinBcryptCost and MaxBcryptCost are the lowest and highest costs of
	// the basic_auth_users hashes (0 without users).
	MinBcryptCost, MaxBcryptCost int
}

// BasicAuthWithoutTLS reports whether credentials would travel in clear text.
func (s Summary) BasicAuthWithoutTLS() bool { return s.HasUsers && !s.TLSEnabled }

// Unprotected reports a web configuration that authenticates nobody:
// neither basic authentication nor a required and verified client
// certificate. An empty file serves in plain HTTP to anyone; TLS without
// client certificates only encrypts.
func (s Summary) Unprotected() bool { return !s.HasUsers && !s.ClientCertsRequired }

// CRLMissing returns the subjects of the CAs of the client CA bundle caPEM
// that no CRL of lists is signed by, and the number of CAs in the bundle.
// At runtime a client certificate is refused unless a CRL of each issuer of
// its verified chain is in the file. Certificates that are not CAs (pinned
// client certificates) are skipped, and so is a CA that issued another CA
// of the bundle which has a CRL: chains end at that intermediate, a trust
// anchor too, and do not need the CRL of the CA above it.
func CRLMissing(caPEM []byte, lists []*x509.RevocationList) (missing []string, total int) {
	var cas []*x509.Certificate
	for block, rest := pem.Decode(caPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil && c.IsCA {
			cas = append(cas, c)
		}
	}
	covered := make([]bool, len(cas))
	for i, ca := range cas {
		for _, l := range lists {
			if bytes.Equal(l.RawIssuer, ca.RawSubject) && l.CheckSignatureFrom(ca) == nil {
				covered[i] = true
				break
			}
		}
	}
	for i, ca := range cas {
		if covered[i] {
			continue
		}
		issuedCovered := false
		for j, other := range cas {
			if j != i && covered[j] && bytes.Equal(other.RawIssuer, ca.RawSubject) && other.CheckSignatureFrom(ca) == nil {
				issuedCovered = true
				break
			}
		}
		if !issuedCovered {
			missing = append(missing, ca.Subject.String())
		}
	}
	return missing, len(cas)
}

// ClientCAPEM returns the client CA bundle of c: the client_ca_file
// content, or the inline client_ca.
func ClientCAPEM(c *web.Config) ([]byte, error) {
	if c.TLSConfig.ClientCAs != "" {
		return os.ReadFile(c.TLSConfig.ClientCAs)
	}
	return []byte(c.TLSConfig.ClientCAsText), nil
}

// Read loads the file at path and summarizes it.
func Read(path string) (Summary, error) {
	c, err := Load(path)
	if err != nil {
		return Summary{}, err
	}
	minCost, maxCost := 0, 0
	for _, h := range c.Users {
		cost, err := bcrypt.Cost([]byte(h)) // checked by Load
		if err != nil {
			continue
		}
		if minCost == 0 || cost < minCost {
			minCost = cost
		}
		maxCost = max(maxCost, cost)
	}
	return Summary{
		MinBcryptCost:       minCost,
		MaxBcryptCost:       maxCost,
		TLSEnabled:          c.TLSConfig.IsEnabled(),
		CertFile:            c.TLSConfig.TLSCertPath,
		KeyFile:             c.TLSConfig.TLSKeyPath,
		ClientCAFile:        c.TLSConfig.ClientCAs,
		CertPEM:             c.TLSConfig.TLSCert,
		ClientCAPEM:         c.TLSConfig.ClientCAsText,
		HasUsers:            len(c.Users) > 0,
		ClientCertsVerified: c.TLSConfig.IsEnabled() && verifies(c.TLSConfig.ClientAuth),
		ClientCertsRequired: c.TLSConfig.IsEnabled() && requiresVerified(c.TLSConfig.ClientAuth),
	}, nil
}

func requiresVerified(clientAuth string) bool {
	required, verified := ClientCertPolicy(clientAuth)
	return required && verified
}

func verifies(clientAuth string) bool {
	_, verified := ClientCertPolicy(clientAuth)
	return verified
}

// AuthorizeWarnings returns why an authorize block could never match on a
// listener with this web configuration: users without basic
// authentication, client_sans without verified client certificates.
func (s Summary) AuthorizeWarnings(users, clientSANs int) []string {
	var w []string
	if users > 0 && !s.HasUsers {
		w = append(w, "authorize users: the web configuration has no basic_auth_users, so no request can match them")
	}
	if clientSANs > 0 && !s.ClientCertsVerified {
		w = append(w, "authorize client_sans: the web configuration does not verify client certificates "+
			"(TLS with client_auth_type RequireAndVerifyClientCert or VerifyClientCertIfGiven), so no request can match them")
	}
	return w
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
func validateClientCA(tc *web.TLSConfig, checkContent bool) error {
	hasCA := tc.ClientCAs != "" || tc.ClientCAsText != ""
	_, verified := ClientCertPolicy(tc.ClientAuth)
	switch {
	case verified && !hasCA:
		return fmt.Errorf("client_auth_type %s verifies client certificates but no client_ca_file or client_ca is set: "+
			"they would be verified against the system roots", NormalizeClientAuth(tc.ClientAuth))
	case !verified && hasCA:
		return fmt.Errorf("client_auth_type %s does not verify client certificates, so the client CA would be ignored: "+
			"use RequireAndVerifyClientCert", NormalizeClientAuth(tc.ClientAuth))
	case !hasCA || !checkContent:
		return nil
	}
	return checkClientCAContent(tc)
}

// caChecks caches the result of client CA checks by content hash: parsing
// a large bundle on every new TLS connection would cost milliseconds.
// Keyed by content, not file metadata, so that a file rewritten keeping its
// size and modification time (cp -p, rsync -t) is checked again.
var caChecks = struct {
	sync.Mutex
	m map[[sha256.Size]byte]error
}{m: map[[sha256.Size]byte]error{}}

// maxCACheckEntries bounds the cache (a few CA contents per process).
const maxCACheckEntries = 64

// checkClientCAContent rejects a client CA without any certificate, which
// would refuse every client.
func checkClientCAContent(tc *web.TLSConfig) error {
	pemData := []byte(tc.ClientCAsText)
	if tc.ClientCAs != "" {
		data, err := os.ReadFile(tc.ClientCAs)
		if err != nil {
			return fmt.Errorf("client_ca_file: %w", err)
		}
		pemData = data
	}
	key := sha256.Sum256(pemData)
	caChecks.Lock()
	err, ok := caChecks.m[key]
	caChecks.Unlock()
	if ok {
		return err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pemData) {
		err = errors.New("the client CA contains no certificate: every client would be refused")
	}
	caChecks.Lock()
	if len(caChecks.m) >= maxCACheckEntries {
		clear(caChecks.m)
	}
	caChecks.m[key] = err
	caChecks.Unlock()
	return err
}

// http2RequiredCiphers are the cipher suites net/http requires for HTTP/2
// over TLS 1.2 (RFC 7540, section 9.2.2).
var http2RequiredCiphers = []web.Cipher{
	web.Cipher(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
	web.Cipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
}

// ValidateHTTP2Ciphers rejects a cipher_suites list net/http refuses to
// serve HTTP/2 with: the listener would stop right after starting,
// stopping the whole process.
func ValidateHTTP2Ciphers(c *web.Config) error {
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

// validateAllowedSANs rejects client_allowed_sans that would not restrict
// clients as written: an empty list (exporter-toolkit then refuses every
// certificate, and panics on clients without one), or a list with a
// client_auth_type that does not verify certificates, since any client
// could then present a self-signed certificate carrying an allowed name.
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

// ReadCRLs reads a client_crl_file: one or more CRLs, PEM ("X509 CRL") or a
// single DER one.
func ReadCRLs(path string) ([]*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCRLs(data)
}

// ParseCRLs parses the content of a client_crl_file.
func ParseCRLs(data []byte) ([]*x509.RevocationList, error) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		l, err := x509.ParseRevocationList(data)
		if err != nil {
			return nil, err
		}
		if err := supportedCRL(l); err != nil {
			return nil, err
		}
		return []*x509.RevocationList{l}, nil
	}
	var lists []*x509.RevocationList
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "X509 CRL" {
			continue
		}
		l, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CRL %d: %w", len(lists)+1, err)
		}
		if err := supportedCRL(l); err != nil {
			return nil, fmt.Errorf("CRL %d: %w", len(lists)+1, err)
		}
		lists = append(lists, l)
	}
	if len(lists) == 0 {
		return nil, errors.New("no X509 CRL found")
	}
	return lists, nil
}

// CRL extensions that limit what a CRL covers: Go parses them without
// applying them, so such a CRL would be taken as complete.
var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// supportedCRL refuses a CRL exporter_proxy cannot apply as written: a
// delta CRL, a partitioned CRL or authority revocation list (issuing
// distribution point), or any critical extension of the CRL or of an
// entry (an indirect CRL's certificate issuer, for example). Accepting it
// as a complete CRL would let revoked certificates through.
func supportedCRL(l *x509.RevocationList) error {
	for _, e := range l.Extensions {
		switch {
		case e.Id.Equal(oidDeltaCRLIndicator):
			return errors.New("delta CRLs are not supported: use complete CRLs")
		case e.Id.Equal(oidIssuingDistributionPoint):
			return errors.New("CRLs with an issuing distribution point (partitioned CRLs, authority revocation lists) are not supported: use complete CRLs")
		case e.Critical:
			return fmt.Errorf("unsupported critical CRL extension %s", e.Id)
		}
	}
	for _, entry := range l.RevokedCertificateEntries {
		for _, e := range entry.Extensions {
			if e.Critical {
				return fmt.Errorf("unsupported critical extension %s on the entry of serial %s", e.Id, entry.SerialNumber)
			}
		}
	}
	return nil
}
