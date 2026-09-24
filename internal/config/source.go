package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	env "github.com/knadh/koanf/providers/env/v2"
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

// jsonFieldSpec describes one structured field overridable via a
// JSON-valued flag/env var — a JSON array for inbound.auth.jwt and acl
// (lists), a JSON object for inbound.auth.saml and inbound.auth.basic
// (each a single optional source). koanf's flat-key env/flag providers
// have no way to express either shape (see loadJSONFieldOverrides' doc
// comment for why), so these fields are deliberately kept out of
// fieldSpecs/envToKey/flagToKey — that table assumes every entry is a
// flat scalar the generic env/posflag providers can decode identically,
// which doesn't hold here. Being absent from those maps also means the
// generic providers' callbacks (envKey/flagKey) simply ignore these
// flags/env vars on their own, since an unrecognized name maps to "" and
// both providers skip empty keys.
type jsonFieldSpec struct {
	koanfKey string
	flagName string
	envName  string
	usage    string
}

var jsonFieldSpecs = []jsonFieldSpec{
	{koanfKey: "inbound.auth.jwt", flagName: "inbound-auth-jwt-json", envName: "INBOUND_AUTH_JWT_JSON",
		usage: "JSON array fully replacing inbound.auth.jwt (env TAP_INBOUND_AUTH_JWT_JSON)"},
	{koanfKey: "inbound.auth.saml", flagName: "inbound-auth-saml-json", envName: "INBOUND_AUTH_SAML_JSON",
		usage: "JSON object fully replacing inbound.auth.saml (env TAP_INBOUND_AUTH_SAML_JSON)"},
	{koanfKey: "inbound.auth.basic", flagName: "inbound-auth-basic-json", envName: "INBOUND_AUTH_BASIC_JSON",
		usage: "JSON object fully replacing inbound.auth.basic (env TAP_INBOUND_AUTH_BASIC_JSON)"},
	{koanfKey: "acl", flagName: "acl-json", envName: "ACL_JSON",
		usage: "JSON array fully replacing acl (env TAP_ACL_JSON)"},
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
	for _, f := range jsonFieldSpecs {
		fs.String(f.flagName, "", f.usage)
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
	// Unknown keys are otherwise ignored, and an ACL nested under inbound
	// would silently leave every request allowed.
	if k.Exists("inbound.acl") {
		return nil, fmt.Errorf("invalid config: inbound.acl is not a config key; acl belongs at the top level")
	}

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
	if err := loadJSONFieldOverrides(k, fs); err != nil {
		return err
	}
	return nil
}

// jsonOverrideValue returns the raw override string for spec — a flag
// (if explicitly set) wins over its env var, mirroring every other
// field's flag > env precedence — or ("", false) if neither is set (or
// set to an empty string — os.LookupEnv's ok is true for
// TAP_..._JSON="", a real-world artifact of container-env templating
// that conditionally renders an empty value rather than omitting the
// var entirely; treating that as "no override" rather than "override
// with invalid JSON" is what lets config load succeed instead of
// failing on every startup/reload with a confusing "invalid JSON:
// unexpected end of JSON input"), in which case the caller must leave
// whatever the file layer already loaded for that key completely
// untouched.
func jsonOverrideValue(fs *pflag.FlagSet, spec jsonFieldSpec) (string, bool) {
	if fs != nil {
		if f := fs.Lookup(spec.flagName); f != nil && f.Changed && f.Value.String() != "" {
			return f.Value.String(), true
		}
	}
	if v, ok := os.LookupEnv(envPrefix + spec.envName); ok && v != "" {
		return v, true
	}
	return "", false
}

// decodeJSONValue parses raw as literal JSON (an array for
// inbound.auth.jwt, an object for inbound.auth.saml — see jsonFieldSpecs).
// The result is left as a generic any rather than decoded straight into
// []JWTSource/*SAMLSource, so it can be handed to koanf and flow through
// the exact same UnmarshalWithConf call — and therefore the same
// "yaml"-tagged field names and duration-string parsing — as the YAML
// file path already uses. A value of the wrong shape (e.g. an object
// where jwt expects an array) parses fine here and is instead rejected
// later by that UnmarshalWithConf/Validate step, same as a malformed
// YAML file would be.
func decodeJSONValue(spec jsonFieldSpec, raw string) (any, error) {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", spec.koanfKey, err)
	}
	return parsed, nil
}

// loadJSONFieldOverrides applies the JSON-blob overrides for
// inbound.auth.jwt and inbound.auth.saml. koanf's flat-key env/flag
// providers have no way to express either "a list of structs" or "an
// optional nested struct" as a single key=value pair — env.Provider's
// TransformFunc and posflag's callback each return one scalar value per
// key, and even koanf's own delimiter-based key nesting
// (maps.Unflatten) only ever builds nested maps, never slices — so
// these fields are handled here instead, entirely outside the
// generic env/flag mechanism, by parsing JSON and injecting the result
// as an already-shaped value via k.Set. A value here fully replaces
// whatever the file layer set for that key, the same "override wins
// outright" semantics every other field already has.
func loadJSONFieldOverrides(k *koanf.Koanf, fs *pflag.FlagSet) error {
	for _, spec := range jsonFieldSpecs {
		raw, ok := jsonOverrideValue(fs, spec)
		if !ok {
			continue
		}
		parsed, err := decodeJSONValue(spec, raw)
		if err != nil {
			return err
		}
		if err := k.Set(spec.koanfKey, parsed); err != nil {
			return fmt.Errorf("%s: %w", spec.koanfKey, err)
		}
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
//
// The file layer is read through newInterpolatingProvider, so every
// ${env:...}/${file:...} reference in it is resolved here — and, since
// this function is also the reload path, re-resolved on every reload.
func loadLayered(path string, fs *pflag.FlagSet) (*Config, error) {
	k := koanf.New(".")
	if path != "" {
		if err := k.Load(newInterpolatingProvider(path), nil); err != nil {
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
