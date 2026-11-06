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
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Built-in defaults, used when neither the `defaults` section nor the
// listener/route sets a value. Keep README.md in sync.
const (
	DefaultTimeout                     = 10 * time.Second
	DefaultMaxBodyBytes          int64 = 4 << 20 // 4 MiB, about max_samples (50000) worth of text
	DefaultMaxSamples                  = 50000
	DefaultMaxConcurrentRequests       = 4
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
	Listen        string
	WebConfigFile string
}

// Listener is one listening address with its authentication and routes.
type Listener struct {
	Name                  string
	Listen                string
	WebConfigFile         string
	MaxConcurrentRequests int
	Routes                []Route
}

// Route maps an exact request path to one metrics source.
type Route struct {
	Path string

	// Source: Upstream (optionally with UnixSocket) or File.
	Upstream   string
	UnixSocket string
	File       string
	MaxAge     time.Duration // file routes only

	Limits Limits
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
	Listen        string `yaml:"listen"`
	WebConfigFile string `yaml:"web_config_file"`
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
	Routes                []fileRoute `yaml:"routes"`
}

type fileRoute struct {
	fileLimits `yaml:",inline"`
	Path       string         `yaml:"path"`
	Upstream   string         `yaml:"upstream"`
	UnixSocket string         `yaml:"unix_socket"`
	File       string         `yaml:"file"`
	MaxAge     *time.Duration `yaml:"max_age"`
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

	cfg := &Config{
		Metrics: MetricsEndpoint{
			Listen:        fc.Metrics.Listen,
			WebConfigFile: fc.Metrics.WebConfigFile,
		},
		Listeners: make([]Listener, 0, len(fc.Listeners)),
	}
	for _, fl := range fc.Listeners {
		l := Listener{
			Name:                  fl.Name,
			Listen:                fl.Listen,
			WebConfigFile:         fl.WebConfigFile,
			MaxConcurrentRequests: valueOr(fl.MaxConcurrentRequests, baseConcurrency),
			Routes:                make([]Route, 0, len(fl.Routes)),
		}
		for _, fr := range fl.Routes {
			l.Routes = append(l.Routes, Route{
				Path:       fr.Path,
				Upstream:   fr.Upstream,
				UnixSocket: fr.UnixSocket,
				File:       fr.File,
				MaxAge:     valueOr(fr.MaxAge, 0),
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
