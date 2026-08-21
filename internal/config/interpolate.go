package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
)

// maxReferencedFileSize bounds how much one ${file:...} reference may pull
// into the configuration. A config value is held in memory for the lifetime
// of the process and re-read on every hot-reload, so a reference pointed at
// something enormous (a log, a device file, the wrong path entirely) should
// fail loudly at load time rather than quietly bloat every reload.
const maxReferencedFileSize = 1 << 20 // 1 MiB

// refOpen is the only sequence that makes '$' special. A bare '$' anywhere
// else is an ordinary character — which is what lets a bcrypt hash
// ("$2y$12$...", the one value in this schema guaranteed to contain '$') be
// pasted into the file verbatim, exactly as htpasswd printed it, with no
// escaping at all.
const refOpen = "${"

// interpolatingProvider reads the YAML config file and resolves every
// ${env:NAME}/${file:PATH} reference in it before koanf ever sees the
// result. It replaces the koanf file.Provider + yaml.Parser pair this
// package used to load with, and is the single reason interpolation applies
// uniformly to every string in the file without any field having to opt in.
//
// Interpolation happens *after* the YAML is parsed, never as text
// substitution on the raw bytes. That ordering is a security property, not
// an implementation detail: a resolved value lands in exactly one node of an
// already-parsed document, so it can never introduce a key, close a block,
// or otherwise alter the document's structure the way templating a config
// file textually can.
//
// Only the file layer is interpolated. The environment/flag layers aren't:
// a TAP_ variable is already an environment value, and the TAP_*_JSON blobs
// deliberately stay literal (see loadJSONFieldOverrides). One consequence
// worth knowing: --config/TAP_CONFIG itself selects the file, so it can
// never contain a reference.
type interpolatingProvider struct {
	path string
	dir  string
}

// newInterpolatingProvider returns a provider for the config file at path.
// The path is cleaned, matching koanf's own file.Provider, and its directory
// is what relative ${file:...} references resolve against — deliberately not
// the process's working directory, which an operator has no reason to reason
// about when writing a config file.
func newInterpolatingProvider(path string) *interpolatingProvider {
	clean := filepath.Clean(path)
	return &interpolatingProvider{path: clean, dir: filepath.Dir(clean)}
}

// ReadBytes is never used: this provider has to parse the document itself in
// order to walk it, so it must be loaded with a nil parser (koanf then calls
// Read instead). Returning an error here mirrors koanf's own file.Provider,
// which implements the opposite half of the interface the same way.
func (p *interpolatingProvider) ReadBytes() ([]byte, error) {
	return nil, errors.New("interpolatingProvider requires a nil parser: load it via Read, not ReadBytes")
}

// Read parses the config file and returns it with every string value
// interpolated.
func (p *interpolatingProvider) Read() (map[string]any, error) {
	// #nosec G304,G703 -- the path is the operator's own --config/TAP_CONFIG
	// value; reading the file it names is this function's entire purpose.
	b, err := os.ReadFile(p.path)
	if err != nil {
		return nil, err
	}

	parsed, err := yaml.Parser().Unmarshal(b)
	if err != nil {
		return nil, err
	}

	out, err := interpolateValue(parsed, p.dir, "")
	if err != nil {
		return nil, err
	}

	m, ok := out.(map[string]any)
	if !ok {
		// An empty (or comments-only) file unmarshals to something that
		// isn't a mapping. koanf merges an empty map harmlessly, and the
		// missing required fields are then caught by Validate, which gives
		// a far better message than anything this layer could.
		return map[string]any{}, nil
	}
	return m, nil
}

// interpolateValue returns v with every string it contains interpolated,
// recursing through maps and slices. keyPath names v's position in the
// document ("inbound.auth.basic.users[0].password_hash") and exists purely
// so a failure says *which* value failed — an unresolvable reference in a
// 200-line config is otherwise undiagnosable from the error alone.
//
// Map keys are never interpolated, only values: a reference resolving into a
// key would change the document's shape, which is exactly the property this
// package's parse-then-interpolate ordering exists to guarantee it can't.
func interpolateValue(v any, dir, keyPath string) (any, error) {
	switch t := v.(type) {
	case string:
		s, err := interpolateString(t, dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", keyPathOrRoot(keyPath), err)
		}
		return s, nil

	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			iv, err := interpolateValue(val, dir, childKeyPath(keyPath, k))
			if err != nil {
				return nil, err
			}
			out[k] = iv
		}
		return out, nil

	case map[any]any:
		// yaml.v3 hands back map[any]any (not map[string]any) for any
		// mapping that has even one non-string key — "on:", "1:", "yes:".
		// koanf normalizes those to strings later, during merge, which is
		// long after this walk: handling only map[string]any here would
		// silently skip interpolation inside such a subtree rather than
		// fail, and a silently un-resolved reference is the worst possible
		// outcome for this feature.
		out := make(map[any]any, len(t))
		for k, val := range t {
			iv, err := interpolateValue(val, dir, childKeyPath(keyPath, fmt.Sprint(k)))
			if err != nil {
				return nil, err
			}
			out[k] = iv
		}
		return out, nil

	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			iv, err := interpolateValue(val, dir, fmt.Sprintf("%s[%d]", keyPath, i))
			if err != nil {
				return nil, err
			}
			out[i] = iv
		}
		return out, nil

	default:
		// Numbers, bools, timestamps, nil — nothing to interpolate. Note
		// this doesn't stop a reference from *feeding* one of those fields:
		// `session_duration: "${env:D}"` is a string here and still decodes
		// to a time.Duration afterwards, since koanf unmarshals with
		// WeaklyTypedInput and a duration hook.
		return v, nil
	}
}

// keyPathOrRoot names the document root for a scalar top-level document,
// where there's no key to report.
func keyPathOrRoot(keyPath string) string {
	if keyPath == "" {
		return "config"
	}
	return keyPath
}

// childKeyPath joins a parent key path with a child key, in the same
// dot-delimited form koanf itself uses for keys.
func childKeyPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// interpolateString resolves every reference in s, left to right.
//
// A resolved value is written to the output and never re-scanned. That
// single-pass rule is load-bearing: if expansions were re-scanned, an
// environment variable holding the literal text "${file:/etc/shadow}" would
// become an arbitrary-file-read primitive for anyone who can set one.
func interpolateString(s, dir string) (string, error) {
	if !strings.Contains(s, refOpen) {
		// Overwhelmingly the common case — every value in a config file
		// with no references at all.
		return s, nil
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}

		// "$${" is the one escape: it emits a literal "${" and consumes
		// nothing else, so the remainder is copied verbatim.
		if strings.HasPrefix(s[i:], "$"+refOpen) {
			b.WriteString(refOpen)
			i += 2
			continue
		}

		if !strings.HasPrefix(s[i:], refOpen) {
			// A bare '$' — not special. This is the branch a bcrypt hash
			// takes, three times, on its way through untouched.
			b.WriteByte('$')
			continue
		}

		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated %q reference: no closing %q", refOpen, "}")
		}
		inner := s[i+2 : i+end]

		val, isRef, err := resolveRef(inner, dir)
		if err != nil {
			return "", err
		}
		if isRef {
			b.WriteString(val)
		} else {
			// Not a reference (no type prefix, e.g. "${HOME}") — emit it
			// exactly as written. Passing it through rather than failing is
			// what keeps a literal "${...}" in some unrelated value legal.
			b.WriteString(s[i : i+end+1])
		}
		i += end
	}
	return b.String(), nil
}

// resolveRef resolves the inside of a "${...}" — "env:NAME" or "file:PATH".
// It reports isRef=false for text that isn't a reference at all, which the
// caller passes through verbatim; a well-formed "type:arg" naming a type
// this package doesn't implement is an error instead, since that's a typo
// in something clearly meant as a reference, and silently forwarding it
// would put the literal text "${vault:secret/db}" into a live config.
func resolveRef(inner, dir string) (val string, isRef bool, err error) {
	kind, arg, found := strings.Cut(inner, ":")
	if !found || !looksLikeRefType(kind) {
		return "", false, nil
	}

	switch kind {
	case "env":
		v, err := resolveEnvRef(arg)
		return v, true, err
	case "file":
		v, err := resolveFileRef(arg, dir)
		return v, true, err
	default:
		return "", false, fmt.Errorf("%s%s}: unknown reference type %q, want %senv:NAME} or %sfile:PATH}",
			refOpen, inner, kind, refOpen, refOpen)
	}
}

// looksLikeRefType reports whether kind is shaped like a reference type at
// all: at least two characters, a letter followed by letters, digits or
// underscores. Anything else means the "${...}" was never a reference
// attempt, so the caller leaves it alone rather than reporting an unknown
// type — which is what keeps a Windows path ("${C:\secrets}") and a bare
// digit ("${1:2}") legal values instead of load errors.
func looksLikeRefType(kind string) bool {
	if len(kind) < 2 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		c := kind[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c == '_' || (c >= '0' && c <= '9')):
		default:
			return false
		}
	}
	return true
}

// resolveEnvRef reads NAME from the environment. An unset variable is an
// error rather than an empty string: every use of this is a value the
// operator meant to supply, and silently substituting "" would hand a
// half-configured proxy to Validate, or worse, past it. A variable that is
// set but empty resolves to "" — that's an explicit choice on the
// operator's side, not an omission.
func resolveEnvRef(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%senv:}: environment variable name is empty", refOpen)
	}
	v, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%senv:%s}: environment variable is not set", refOpen, name)
	}
	return v, nil
}

// resolveFileRef reads the file at path, resolving a relative path against
// dir (the config file's own directory). Exactly one trailing newline is
// stripped, so `printf 'secret' > f` and `echo secret > f` produce the same
// value — deliberately not a full TrimSpace, which would silently corrupt a
// secret that genuinely ends in whitespace.
//
// The file is read fresh on every config load, so it re-resolves on every
// hot-reload — but nothing watches it: the config watcher only watches the
// config file's own directory (see Watcher), so rotating a referenced secret
// takes effect on the next config reload or restart, not immediately.
func resolveFileRef(path, dir string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%sfile:}: path is empty", refOpen)
	}

	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(dir, full)
	}

	// #nosec G703 -- see the ReadFile below: the path comes from the
	// operator's own config file, which already dictates everything else
	// this process does.
	info, err := os.Stat(full)
	if err != nil {
		return "", fmt.Errorf("%sfile:%s}: %w", refOpen, path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%sfile:%s}: is a directory, not a file", refOpen, path)
	}
	if info.Size() > maxReferencedFileSize {
		return "", fmt.Errorf("%sfile:%s}: file is %d bytes, over the %d byte limit",
			refOpen, path, info.Size(), maxReferencedFileSize)
	}

	// #nosec G304,G703 -- the path comes from the operator's own config file,
	// which already dictates everything else this process does; reading it
	// is the reference's entire purpose.
	b, err := os.ReadFile(full)
	if err != nil {
		return "", fmt.Errorf("%sfile:%s}: %w", refOpen, path, err)
	}

	s := string(b)
	switch {
	case strings.HasSuffix(s, "\r\n"):
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "\n"):
		s = s[:len(s)-1]
	}
	return s, nil
}
