package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const promLabelBase = `
listen_addr: ":0"
target: "http://localhost:9000"
inbound:
  auth:
    jwt:
      - name: idp
        issuer: "https://idp.example.com"
        jwks_url: "https://idp.example.com/jwks"
`

const promLabelValid = promLabelBase + `
outbound:
  prom_label_proxy:
    path_prefixes:
      - /api/prom
      - /prometheus/
      - /a
    rules:
      - principals:
          - mode: jwt
            source: idp
        labels:
          - name: namespace
            claim: groups
            pattern: "tenant-(.+)"
    passthrough_paths:
      - /api/v1/status/buildinfo
      - /ui/*
`

func TestPromLabelProxy_Loads(t *testing.T) {
	cfg, err := loadLayered(writeTempConfig(t, promLabelValid), nil)
	require.NoError(t, err)
	p := cfg.Outbound.PromLabelProxy
	require.NotNil(t, p)
	assert.Equal(t, []string{"/prometheus", "/api/prom", "/a"}, p.Prefixes())
	assert.Equal(t, []string{"a", "b"}, p.Rules[0].Labels[0].Values([]string{"tenant-b", "other", "tenant-a", "tenant-a"}))
}

func TestPromLabelProxy_DefaultPrefixIsRoot(t *testing.T) {
	cfg, err := loadLayered(writeTempConfig(t, promLabelBase+`
outbound:
  prom_label_proxy:
    rules:
      - principals:
          - mode: jwt
        labels:
          - name: namespace
            claim: sub
`), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{""}, cfg.Outbound.PromLabelProxy.Prefixes())
}

func TestPromLabel_Values(t *testing.T) {
	load := func(t *testing.T, pattern string) PromLabel {
		t.Helper()
		l := PromLabel{Name: "ns", Claim: "c", Pattern: pattern}
		require.NoError(t, l.validate())
		return l
	}

	t.Run("no pattern keeps every value", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b"}, load(t, "").Values([]string{"b", "a"}))
	})
	t.Run("pattern is anchored", func(t *testing.T) {
		assert.Empty(t, load(t, "tenant").Values([]string{"my-tenant-x"}))
	})
	t.Run("alternation is anchored as a whole", func(t *testing.T) {
		assert.Empty(t, load(t, "a|b").Values([]string{"xa", "bx"}))
	})
	t.Run("no capture group keeps the whole value", func(t *testing.T) {
		assert.Equal(t, []string{"team-x"}, load(t, "team-.+").Values([]string{"team-x", "other"}))
	})
	t.Run("an empty value is never kept", func(t *testing.T) {
		assert.Empty(t, load(t, "").Values([]string{""}))
		assert.Empty(t, load(t, "tenant-(.*)").Values([]string{"tenant-"}))
	})
}

func TestPromLabelProxy_Invalid(t *testing.T) {
	block := func(rest string) string { return promLabelBase + "outbound:\n  prom_label_proxy:\n" + rest }
	rule := func(label string) string {
		return block("    rules:\n      - principals:\n          - mode: jwt\n            source: idp\n        labels:\n" + label)
	}

	tests := []struct {
		name, yaml, want string
	}{
		{"no rules", block("    exempt:\n      - mode: jwt\n        source: idp\n"), "rules is required"},
		{"empty block", promLabelBase + "outbound:\n  prom_label_proxy:\n", "is empty"},
		{"no principals", block("    rules:\n      - labels:\n          - name: a\n            claim: b\n"), "principals is required"},
		{"no labels", block("    rules:\n      - principals:\n          - mode: jwt\n"), "labels is required"},
		{"bad label name", rule("          - name: 1bad\n            claim: sub\n"), "not a valid label name"},
		{"no claim", rule("          - name: ns\n"), "claim is required"},
		{"duplicate label", rule("          - name: ns\n            claim: a\n          - name: ns\n            claim: b\n"), "listed twice"},
		{"bad pattern", rule("          - name: ns\n            claim: a\n            pattern: \"(\"\n"), "pattern"},
		{"anchor escape", rule("          - name: ns\n            claim: a\n            pattern: \"a)|(b\"\n"), "pattern"},
		{"two groups", rule("          - name: ns\n            claim: a\n            pattern: \"(a)(b)\"\n"), "capture groups"},
		{"unknown source", block("    rules:\n      - principals:\n          - mode: jwt\n            source: nope\n        labels:\n          - name: a\n            claim: b\n"), "does not name"},
		{"basic rule", block("    rules:\n      - principals:\n          - mode: basic\n            username: a\n        labels:\n          - name: a\n            claim: b\n"), "no claims to map"},
		{"bare exempt", block("    exempt:\n      - mode: jwt\n    rules:\n      - principals:\n          - mode: jwt\n        labels:\n          - name: a\n            claim: b\n"), "exempt[0]"},
		{"bad passthrough", block("    passthrough_paths:\n      - nope\n    rules:\n      - principals:\n          - mode: jwt\n        labels:\n          - name: a\n            claim: b\n"), "passthrough_paths[0]"},
		{"wildcard prefix", block("    path_prefixes:\n      - /x/*\n    rules:\n      - principals:\n          - mode: jwt\n        labels:\n          - name: a\n            claim: b\n"), "path_prefixes[0]"},
		{"typo in block", block("    rulez: []\n    rules:\n      - principals:\n          - mode: jwt\n        labels:\n          - name: a\n            claim: b\n"), "rulez"},
		{"typo in rule", block("    rules:\n      - principals:\n          - mode: jwt\n        label:\n          - name: a\n            claim: b\n"), "label"},
		{"typo of block", promLabelBase + "outbound:\n  prom_label_proxi:\n    rules: []\n", "prom_label_proxi"},
		{"typo of outbound", promLabelBase + "outbond:\n  prom_label_proxy:\n    rules: []\n", "outbond"},
		{"outbound in the wrong case", promLabelBase + "Outbound:\n  prom_label_proxi:\n    rules: []\n", "Outbound"},
		{
			"no inbound auth",
			"listen_addr: \":0\"\ntarget: \"http://localhost:9000\"\noutbound:\n  prom_label_proxy:\n    rules:\n      - principals:\n          - mode: jwt\n        labels:\n          - name: a\n            claim: b\n",
			"requires an inbound auth method",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadLayered(writeTempConfig(t, tt.yaml), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestPromLabelProxy_JSONOverride(t *testing.T) {
	t.Setenv("TAP_OUTBOUND_PROM_LABEL_PROXY_JSON", `{"rules":[{"principals":[{"mode":"jwt"}],"labels":[{"name":"ns","claim":"sub"}]}]}`)
	cfg, err := loadLayered(writeTempConfig(t, promLabelBase), newFlagSet(t))
	require.NoError(t, err)
	require.NotNil(t, cfg.Outbound.PromLabelProxy)
	assert.Equal(t, "ns", cfg.Outbound.PromLabelProxy.Rules[0].Labels[0].Name)
}
