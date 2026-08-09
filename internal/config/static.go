package config

// StaticSource is a ConfigSource (see the proxy package) that never
// changes. It's used when the proxy is configured entirely from CLI
// flags and/or environment variables — no file, so nothing to watch.
type StaticSource struct {
	cfg *Config
}

// NewStaticSource wraps an already-validated Config as a ConfigSource.
func NewStaticSource(cfg *Config) *StaticSource {
	return &StaticSource{cfg: cfg}
}

// Current always returns the same Config this source was built with.
func (s *StaticSource) Current() *Config {
	return s.cfg
}
