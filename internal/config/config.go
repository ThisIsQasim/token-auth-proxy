// Package config loads and validates the proxy's YAML configuration and
// watches it on disk for live, hot-reloadable changes.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// defaultListenAddr is used when listen_addr is omitted from the config file.
const defaultListenAddr = ":8080"

// Default timeouts applied to any zero-value timeout field.
const (
	defaultReadHeaderTimeout     = 5 * time.Second
	defaultReadTimeout           = 30 * time.Second
	defaultWriteTimeout          = 30 * time.Second
	defaultIdleTimeout           = 120 * time.Second
	defaultDialTimeout           = 5 * time.Second
	defaultResponseHeaderTimeout = 15 * time.Second
)

// TimeoutConfig holds the HTTP server/client timeouts used by the proxy.
// These are only read once at startup — see Config's doc comment.
type TimeoutConfig struct {
	ReadHeader     time.Duration `yaml:"read_header,omitempty"`
	Read           time.Duration `yaml:"read,omitempty"`
	Write          time.Duration `yaml:"write,omitempty"`
	Idle           time.Duration `yaml:"idle,omitempty"`
	Dial           time.Duration `yaml:"dial,omitempty"`
	ResponseHeader time.Duration `yaml:"response_header,omitempty"`
}

// Config is the proxy's configuration, as loaded from a YAML file.
//
// Only Target is hot-reloaded while the process is running: ListenAddr and
// Timeouts are consumed once at startup to build the listener and outbound
// transport, and changing them requires a process restart.
type Config struct {
	ListenAddr string        `yaml:"listen_addr"`
	Target     string        `yaml:"target"`
	Timeouts   TimeoutConfig `yaml:"timeouts,omitempty"`

	targetURL *url.URL
}

// Load reads and parses the YAML file at path, applies defaults, and
// validates the result. The returned Config is ready to use — its
// TargetURL() is guaranteed non-nil on success.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied -config flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// applyDefaults fills in zero-value fields with their defaults.
func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = defaultListenAddr
	}
	if c.Timeouts.ReadHeader == 0 {
		c.Timeouts.ReadHeader = defaultReadHeaderTimeout
	}
	if c.Timeouts.Read == 0 {
		c.Timeouts.Read = defaultReadTimeout
	}
	if c.Timeouts.Write == 0 {
		c.Timeouts.Write = defaultWriteTimeout
	}
	if c.Timeouts.Idle == 0 {
		c.Timeouts.Idle = defaultIdleTimeout
	}
	if c.Timeouts.Dial == 0 {
		c.Timeouts.Dial = defaultDialTimeout
	}
	if c.Timeouts.ResponseHeader == 0 {
		c.Timeouts.ResponseHeader = defaultResponseHeaderTimeout
	}
}

// Validate checks the config for correctness and, on success, caches the
// parsed target URL for TargetURL() to return.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr %q: %w", c.ListenAddr, err)
	}

	if c.Target == "" {
		return fmt.Errorf("target is required")
	}

	u, err := url.ParseRequestURI(c.Target)
	if err != nil {
		return fmt.Errorf("target %q: %w", c.Target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target %q: scheme must be http or https, got %q", c.Target, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("target %q: missing host", c.Target)
	}

	c.targetURL = u
	return nil
}

// TargetURL returns the parsed backend target URL. It is nil until
// Validate has succeeded.
func (c *Config) TargetURL() *url.URL {
	return c.targetURL
}
