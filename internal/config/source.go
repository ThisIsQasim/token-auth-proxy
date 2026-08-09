package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	env "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// envPrefix namespaces every environment variable this proxy reads, so
// it never collides with an unrelated variable an operator might have
// set in a shared environment (a container, a CI runner, ...).
const envPrefix = "TAP_"

// fieldSpec is the single source of truth for every config field
// reachable from outside a YAML file: its koanf key (matching Config's
// existing yaml struct tags), its CLI flag name, and its environment
// variable suffix (after envPrefix). RegisterFlags, envKey, and flagKey
// are all generated from this one table, so adding a field means
// editing this list, not three separate pieces of parsing code.
type fieldSpec struct {
	koanfKey string
	flagName string
	envName  string
	usage    string
	duration bool
}

var fieldSpecs = []fieldSpec{
	{koanfKey: "config", flagName: "config", envName: "CONFIG",
		usage: "path to a YAML config file; enables hot-reload (env TAP_CONFIG)"},
	{koanfKey: "listen_addr", flagName: "listen-addr", envName: "LISTEN_ADDR",
		usage: "address to listen on (env TAP_LISTEN_ADDR)"},
	{koanfKey: "target", flagName: "target", envName: "TARGET",
		usage: "backend URL to forward every request to (env TAP_TARGET); required if --config is not set"},
	{koanfKey: "timeouts.read_header", flagName: "timeout-read-header", envName: "TIMEOUT_READ_HEADER",
		usage: "response header read timeout (env TAP_TIMEOUT_READ_HEADER)", duration: true},
	{koanfKey: "timeouts.read", flagName: "timeout-read", envName: "TIMEOUT_READ",
		usage: "request read timeout (env TAP_TIMEOUT_READ)", duration: true},
	{koanfKey: "timeouts.write", flagName: "timeout-write", envName: "TIMEOUT_WRITE",
		usage: "response write timeout (env TAP_TIMEOUT_WRITE)", duration: true},
	{koanfKey: "timeouts.idle", flagName: "timeout-idle", envName: "TIMEOUT_IDLE",
		usage: "keep-alive idle timeout (env TAP_TIMEOUT_IDLE)", duration: true},
	{koanfKey: "timeouts.dial", flagName: "timeout-dial", envName: "TIMEOUT_DIAL",
		usage: "backend dial timeout (env TAP_TIMEOUT_DIAL)", duration: true},
	{koanfKey: "timeouts.response_header", flagName: "timeout-response-header", envName: "TIMEOUT_RESPONSE_HEADER",
		usage: "backend response header timeout (env TAP_TIMEOUT_RESPONSE_HEADER)", duration: true},
}

var (
	envToKey  = make(map[string]string, len(fieldSpecs))
	flagToKey = make(map[string]string, len(fieldSpecs))
)

func init() {
	for _, f := range fieldSpecs {
		envToKey[f.envName] = f.koanfKey
		flagToKey[f.flagName] = f.koanfKey
	}
}

// RegisterFlags registers every recognized flag on fs with a zero-value
// default. Defaults are deliberately not baked in here: Config.applyDefaults
// fills them in later, once the file/env/flag layers have all been merged
// by decode, so a default value never needs to live in two places.
func RegisterFlags(fs *pflag.FlagSet) {
	for _, f := range fieldSpecs {
		if f.duration {
			fs.Duration(f.flagName, 0, f.usage)
		} else {
			fs.String(f.flagName, "", f.usage)
		}
	}
}

// envKey maps a TAP_-prefixed environment variable name to its koanf
// key. Returning ("", nil) tells the env provider to ignore the
// variable — either it doesn't have the prefix, or it has the prefix
// but isn't one this proxy recognizes.
func envKey(k, v string) (string, any) {
	koanfKey, ok := envToKey[strings.TrimPrefix(k, envPrefix)]
	if !ok {
		return "", nil
	}
	return koanfKey, v
}

// flagKey returns a posflag callback mapping a CLI flag's dash-cased
// name to its koanf key, reading the flag's typed value via fs (so a
// duration flag decodes as a time.Duration, not a string that would
// need re-parsing).
func flagKey(fs *pflag.FlagSet) func(f *pflag.Flag) (string, any) {
	return func(f *pflag.Flag) (string, any) {
		koanfKey, ok := flagToKey[f.Name]
		if !ok {
			return "", nil
		}
		return koanfKey, posflag.FlagVal(fs, f)
	}
}

// decode unmarshals k into a Config using its existing `yaml` struct
// tags, applies defaults, and validates the result. This is the single
// "sources to validated Config" step shared by every entry point: Load,
// Watcher's initial load and every subsequent reload, and the static
// flags/env path in Resolve.
func decode(k *koanf.Koanf) (*Config, error) {
	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{Tag: "yaml"}); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// loadOverrides loads environment variables and then CLI flags into k,
// in that precedence order — flags are loaded last, so they win. This
// is the override layer applied on top of an optional file by
// loadLayered, or used on its own by Resolve to build a fully static
// Config.
func loadOverrides(k *koanf.Koanf, fs *pflag.FlagSet) error {
	if err := k.Load(env.Provider(".", env.Opt{Prefix: envPrefix, TransformFunc: envKey}), nil); err != nil {
		return fmt.Errorf("read environment: %w", err)
	}
	if err := k.Load(posflag.ProviderWithFlag(fs, ".", k, flagKey(fs)), nil); err != nil {
		return fmt.Errorf("read flags: %w", err)
	}
	return nil
}

// loadLayered builds a Config by merging, in increasing precedence: an
// optional file at path, environment variables, and CLI flags
// (flag > env > file > built-in default). It is rebuilt from scratch on
// every call — koanf has no notion of "reload only what changed" — and
// that matters for correctness, not just simplicity: re-applying the
// override layer on top of a freshly-read file on every call is what
// makes a CLI/env override keep winning across every hot-reload, not
// just the first one. fs may be nil, meaning no override layer at all
// (a plain file load).
func loadLayered(path string, fs *pflag.FlagSet) (*Config, error) {
	k := koanf.New(".")
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	if fs != nil {
		if err := loadOverrides(k, fs); err != nil {
			return nil, err
		}
	}
	return decode(k)
}

// Source is the result of resolving CLI flags and environment
// variables. Exactly one of ConfigPath or Config is meaningful:
// ConfigPath non-empty means the caller should use Load/NewWatcher for
// hot-reload (env/flag overrides are re-applied on every reload, not
// just here); otherwise Config is a complete, validated configuration
// that will never change.
type Source struct {
	ConfigPath string
	Config     *Config
	FlagSet    *pflag.FlagSet
}

// Resolve reads environment variables and fs's already-parsed flags to
// decide between file+hot-reload mode and static mode, following
// loadLayered's same precedence (flag > env > file > default) — "config"
// is just another key in that same merge, so --config and TAP_CONFIG are
// resolved exactly like every other field.
func Resolve(fs *pflag.FlagSet) (*Source, error) {
	k := koanf.New(".")
	if err := loadOverrides(k, fs); err != nil {
		return nil, err
	}

	if path := k.String("config"); path != "" {
		return &Source{ConfigPath: path, FlagSet: fs}, nil
	}

	cfg, err := decode(k)
	if err != nil {
		return nil, err
	}
	return &Source{Config: cfg, FlagSet: fs}, nil
}
