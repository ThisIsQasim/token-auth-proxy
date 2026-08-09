// Package config loads and validates the proxy's YAML configuration and
// watches it on disk for live, hot-reloadable changes.
package config

import (
	"fmt"
	"net"
	"net/url"
	"time"
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
