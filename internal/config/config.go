// Package config loads the exporter_proxy configuration file.
//
// The file is decoded strictly (unknown keys are errors), then global
// defaults are applied and overridden per listener or per route, so that the
// rest of the program only sees fully resolved values.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Built-in defaults, used when neither the `defaults` section nor the
// listener/route sets a value. Keep README.md in sync.
const (
	DefaultTimeout                     = 10 * time.Second
	DefaultMaxBodyBytes          int64 = 2 << 20 // 2 MiB, ample for typical exporters (node_exporter: ~0.1-0.5 MiB)
	DefaultMaxSamples                  = 24000   // node_exporter: a few thousand samples
	DefaultMaxConcurrentRequests       = 2

	// MaxMaxBodyBytes bounds max_body_bytes: the whole body is held in
	// memory, and larger values would overflow size computations.
	MaxMaxBodyBytes int64 = 1 << 30 // 1 GiB
)

// Config is the resolved configuration: every default has been applied.
type Config struct {
	Metrics   MetricsEndpoint
	Listeners []Listener

	// Hash identifies the configuration file content: the first 48 bits of
	// the SHA-256 of the raw bytes. 48 bits fit exactly in a float64, so the
	// value survives being exported as a Prometheus gauge.
	Hash uint64
}

// HashString returns Hash as 12 hexadecimal digits, for logs.
func (c *Config) HashString() string {
	return fmt.Sprintf("%012x", c.Hash)
}

// hash48 returns the first 48 bits of the SHA-256 of data.
func hash48(data []byte) uint64 {
	sum := sha256.Sum256(data)
	return binary.BigEndian.Uint64(sum[:8]) >> 16
}

// MetricsEndpoint is where exporter_proxy exposes its own metrics.
type MetricsEndpoint struct {
	Listen          string
	WebConfigFile   string
	AllowedNetworks []netip.Prefix // nil: every client address
	// ServiceDiscovery enables the Prometheus HTTP service discovery
	// endpoint; nil: disabled.
	ServiceDiscovery *ServiceDiscovery
}

// ServiceDiscovery describes the targets the discovery endpoint lists.
type ServiceDiscovery struct {
	// Host is the name or address Prometheus reaches the listeners at.
	Host string
	// Labels are added to every target.
	Labels map[string]string
}

// Listener is one listening address with its authentication and routes.
type Listener struct {
	Name                  string
	Listen                string
	WebConfigFile         string
	MaxConcurrentRequests int
	// AllowedNetworks are the client networks allowed to connect; nil:
	// every client address.
	AllowedNetworks []netip.Prefix
	Routes          []Route
}

// Route maps an exact request path to one metrics source.
type Route struct {
	Path string

	// Source: Upstream (optionally with UnixSocket or UpstreamTLS) or File.
	Upstream    string
	UpstreamTLS *UpstreamTLS // https:// upstreams only; nil: system roots
	UnixSocket  string
	File        string
	MaxAge      time.Duration // file routes only

	// Authorize restricts the route to some of the listener's clients;
	// nil: every client the listener authenticates.
	Authorize *Authorize

	Limits Limits
}

// UpstreamTLS configures the TLS connection to an https:// upstream. The
// upstream certificate is always verified.
type UpstreamTLS struct {
	CAFile     string // CA bundle verifying the upstream; empty: system roots
	CertFile   string // client certificate (mTLS), with KeyFile
	KeyFile    string
	ServerName string // name verified in the upstream certificate; empty: the URL host
}

// Authorize lists who may read a route: a request is allowed when its
// basic authentication user is in Users, or when its verified client
// certificate has a subject alternative name in ClientSANs.
type Authorize struct {
	Users      []string
	ClientSANs []string
}

// Limits bound the work done for one request on a route.
type Limits struct {
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxSamples   int
}

// File structures: what the YAML file contains. Pointers distinguish an
// unset value (inherit) from an explicit one.

type fileConfig struct {
	Metrics   fileMetrics    `yaml:"metrics"`
	Defaults  fileDefaults   `yaml:"defaults"`
	Listeners []fileListener `yaml:"listeners"`
}

type fileMetrics struct {
	Listen           string                `yaml:"listen"`
	WebConfigFile    string                `yaml:"web_config_file"`
	AllowedNetworks  []string              `yaml:"allowed_networks"`
	ServiceDiscovery *fileServiceDiscovery `yaml:"service_discovery"`
}

type fileServiceDiscovery struct {
	Host   string            `yaml:"host"`
	Labels map[string]string `yaml:"labels"`
}

type fileLimits struct {
	Timeout      *time.Duration `yaml:"timeout"`
	MaxBodyBytes *int64         `yaml:"max_body_bytes"`
	MaxSamples   *int           `yaml:"max_samples"`
}

type fileDefaults struct {
	fileLimits            `yaml:",inline"`
	MaxConcurrentRequests *int `yaml:"max_concurrent_requests"`
}

type fileListener struct {
	Name                  string      `yaml:"name"`
	Listen                string      `yaml:"listen"`
	WebConfigFile         string      `yaml:"web_config_file"`
	MaxConcurrentRequests *int        `yaml:"max_concurrent_requests"`
	AllowedNetworks       []string    `yaml:"allowed_networks"`
	Routes                []fileRoute `yaml:"routes"`
}

type fileRoute struct {
	fileLimits `yaml:",inline"`
	Path       string         `yaml:"path"`
	Upstream   string         `yaml:"upstream"`
	UnixSocket string         `yaml:"unix_socket"`
	File       string         `yaml:"file"`
	MaxAge     *time.Duration `yaml:"max_age"`
	Authorize  *fileAuthorize `yaml:"authorize"`
	// UpstreamTLS is decoded as is: no inheritance.
	UpstreamTLS *fileUpstreamTLS `yaml:"upstream_tls"`
}

type fileUpstreamTLS struct {
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
}

type fileAuthorize struct {
	Users      []string `yaml:"users"`
	ClientSANs []string `yaml:"client_sans"`
}

// Load reads and decodes the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Callers log the path next to the error, do not repeat it here.
	return Parse(data)
}

// Parse decodes and validates a configuration document, then resolves
// defaults. Validation problems are returned together as a *ValidationError.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty configuration")
		}
		return nil, flattenYAMLError(err)
	}
	// A second document would be silently ignored: reject it.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain a single YAML document")
	}

	if err := validate(&fc); err != nil {
		return nil, err
	}

	cfg := resolve(&fc)
	cfg.Hash = hash48(data)
	return cfg, nil
}

// resolve applies the precedence: route/listener value, then the `defaults`
// section, then the built-in default.
func resolve(fc *fileConfig) *Config {
	base := Limits{
		Timeout:      valueOr(fc.Defaults.Timeout, DefaultTimeout),
		MaxBodyBytes: valueOr(fc.Defaults.MaxBodyBytes, DefaultMaxBodyBytes),
		MaxSamples:   valueOr(fc.Defaults.MaxSamples, DefaultMaxSamples),
	}
	baseConcurrency := valueOr(fc.Defaults.MaxConcurrentRequests, DefaultMaxConcurrentRequests)

	var sd *ServiceDiscovery
	if f := fc.Metrics.ServiceDiscovery; f != nil {
		sd = &ServiceDiscovery{Host: f.Host, Labels: f.Labels}
	}
	cfg := &Config{
		Metrics: MetricsEndpoint{
			Listen:           fc.Metrics.Listen,
			WebConfigFile:    fc.Metrics.WebConfigFile,
			AllowedNetworks:  networks(fc.Metrics.AllowedNetworks),
			ServiceDiscovery: sd,
		},
		Listeners: make([]Listener, 0, len(fc.Listeners)),
	}
	for _, fl := range fc.Listeners {
		l := Listener{
			Name:                  fl.Name,
			Listen:                fl.Listen,
			WebConfigFile:         fl.WebConfigFile,
			MaxConcurrentRequests: valueOr(fl.MaxConcurrentRequests, baseConcurrency),
			AllowedNetworks:       networks(fl.AllowedNetworks),
			Routes:                make([]Route, 0, len(fl.Routes)),
		}
		for _, fr := range fl.Routes {
			l.Routes = append(l.Routes, Route{
				Path:        fr.Path,
				Upstream:    fr.Upstream,
				UpstreamTLS: upstreamTLSOf(fr.UpstreamTLS),
				UnixSocket:  fr.UnixSocket,
				File:        fr.File,
				MaxAge:      valueOr(fr.MaxAge, 0),
				Authorize:   authorizeOf(fr.Authorize),
				Limits: Limits{
					Timeout:      valueOr(fr.Timeout, base.Timeout),
					MaxBodyBytes: valueOr(fr.MaxBodyBytes, base.MaxBodyBytes),
					MaxSamples:   valueOr(fr.MaxSamples, base.MaxSamples),
				},
			})
		}
		cfg.Listeners = append(cfg.Listeners, l)
	}
	return cfg
}

func upstreamTLSOf(f *fileUpstreamTLS) *UpstreamTLS {
	if f == nil {
		return nil
	}
	return &UpstreamTLS{CAFile: f.CAFile, CertFile: f.CertFile, KeyFile: f.KeyFile, ServerName: f.ServerName}
}

func authorizeOf(fa *fileAuthorize) *Authorize {
	if fa == nil {
		return nil
	}
	return &Authorize{Users: fa.Users, ClientSANs: fa.ClientSANs}
}

// networks returns validated allowed_networks entries as prefixes, nil when
// unset.
func networks(entries []string) []netip.Prefix {
	if entries == nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		p, err := ParseNetwork(e)
		if err != nil {
			panic(fmt.Sprintf("allowed_networks entry %q passed validation: %v", e, err)) // validated before
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

// ParseNetwork parses an allowed_networks entry: a network in CIDR
// notation, written with its host bits cleared (192.0.2.0/24), or a single
// address. IPv4-mapped IPv6 forms are converted to IPv4, like client
// addresses are.
func ParseNetwork(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p != p.Masked() {
			return netip.Prefix{}, fmt.Errorf("host bits set, use %q", p.Masked().String())
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Zone() != "" {
		return netip.Prefix{}, errors.New("an IPv6 zone is not allowed")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func valueOr[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// flattenYAMLError turns yaml.v3's multi-line type errors into a single line,
// so that each log event stays on one line.
func flattenYAMLError(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return errors.New(strings.Join(te.Errors, "; "))
	}
	return err
}
