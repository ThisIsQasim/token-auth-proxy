package authn

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

// sharedBasicHash is cached per process for the same reason
// sharedRSAKey is: bcrypt is deliberately slow, and every case here
// wants a valid hash. MinCost, since nothing under test depends on the
// cost factor.
var sharedBasicHash = sync.OnceValues(func() (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	return string(h), err
})

func basicSourceFor(t *testing.T) config.BasicSource {
	t.Helper()
	hash, err := sharedBasicHash()
	require.NoError(t, err)
	return config.BasicSource{
		Realm: "test-realm",
		Users: []config.BasicUser{{Username: "alice", PasswordHash: hash}},
	}
}

// countingRegistry returns a registry whose bcrypt compares are counted,
// so tests can assert on cache behavior directly instead of by timing.
func countingRegistry(t *testing.T) (*BasicRegistry, func() int) {
	t.Helper()
	reg := NewBasicRegistry(testLogger())

	var mu sync.Mutex
	var n int
	real := reg.compareHash
	reg.compareHash = func(hash, password []byte) error {
		mu.Lock()
		n++
		mu.Unlock()
		return real(hash, password)
	}

	return reg, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func configWithBasic(src config.BasicSource) *config.Config {
	return &config.Config{Inbound: config.InboundConfig{Auth: config.InboundAuthConfig{Basic: &src}}}
}

func TestBasicRegistry_Verify(t *testing.T) {
	src := basicSourceFor(t)

	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "correct credential", username: "alice", password: "hunter2", want: true},
		{name: "wrong password", username: "alice", password: "wrong", want: false},
		{name: "unknown user", username: "mallory", password: "hunter2", want: false},
		{name: "empty password", username: "alice", password: "", want: false},
		{name: "username is not compared case-insensitively", username: "Alice", password: "hunter2", want: false},
		{
			name:     "absurdly long credential is refused without a compare",
			username: "alice",
			password: string(make([]byte, maxBasicCredentialLen+1)),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewBasicRegistry(testLogger())
			got, err := reg.Verify(src, tt.username, tt.password)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBasicRegistry_Verify_CachesSuccess(t *testing.T) {
	src := basicSourceFor(t)
	reg, compares := countingRegistry(t)

	for range 5 {
		ok, err := reg.Verify(src, "alice", "hunter2")
		require.NoError(t, err)
		assert.True(t, ok)
	}

	assert.Equal(t, 1, compares(), "a repeated credential must be verified with bcrypt exactly once")
}

func TestBasicRegistry_Verify_CachesFailure(t *testing.T) {
	src := basicSourceFor(t)
	reg, compares := countingRegistry(t)

	for range 5 {
		ok, err := reg.Verify(src, "alice", "wrong")
		require.NoError(t, err)
		assert.False(t, ok)
	}

	assert.Equal(t, 1, compares(), "a repeated wrong password must not cost a bcrypt compare every time")

	// The negative cache must not be able to mask a later correct
	// password for the same user.
	ok, err := reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBasicRegistry_Verify_CacheExpires(t *testing.T) {
	src := basicSourceFor(t)
	reg, compares := countingRegistry(t)

	now := time.Now()
	reg.now = func() time.Time { return now }

	ok, err := reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	require.True(t, ok)

	now = now.Add(basicCacheTTL - time.Second)
	_, err = reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	assert.Equal(t, 1, compares(), "an entry within its TTL must still be served from cache")

	now = now.Add(2 * time.Second)
	ok, err = reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 2, compares(), "an expired entry must be re-verified")
}

func TestBasicRegistry_Reconcile_DropsCacheOnlyWhenTheSourceChanges(t *testing.T) {
	src := basicSourceFor(t)
	reg, compares := countingRegistry(t)

	cfg := configWithBasic(src)
	reg.Reconcile(cfg)
	_, err := reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	require.Equal(t, 1, compares())

	// Watcher publishes a brand-new *Config on every reload, even a
	// content-identical one, and reloads fire on unrelated events in the
	// config directory. Those must not cost the cache.
	reg.Reconcile(configWithBasic(src))
	_, err = reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	assert.Equal(t, 1, compares(), "an identical source under a new Config pointer must keep the cache")

	// Rotating the hash (here: removing the user) must invalidate it.
	changed := src
	changed.Users = []config.BasicUser{{Username: "bob", PasswordHash: src.Users[0].PasswordHash}}
	reg.Reconcile(configWithBasic(changed))

	_, err = reg.Verify(src, "alice", "hunter2")
	require.NoError(t, err)
	assert.Equal(t, 2, compares(), "a changed source must drop the cache")
}

func TestBasicRegistry_Verify_UnknownUserStillCompares(t *testing.T) {
	src := basicSourceFor(t)
	reg, compares := countingRegistry(t)

	ok, err := reg.Verify(src, "mallory", "hunter2")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 1, compares(),
		"an unknown username must still pay for a compare, or response timing reveals which usernames exist")
}

func TestBasicRegistry_Verify_CacheCapClears(t *testing.T) {
	src := basicSourceFor(t)
	reg := NewBasicRegistry(testLogger())
	// Nothing here needs a real hash comparison; only the bookkeeping.
	reg.compareHash = func(hash, password []byte) error { return nil }

	for i := range maxBasicCacheEntries + 10 {
		_, err := reg.Verify(src, "alice", string(rune(i))+"pw")
		require.NoError(t, err)
	}

	reg.mu.Lock()
	size := len(reg.cache)
	reg.mu.Unlock()
	assert.LessOrEqual(t, size, maxBasicCacheEntries, "the cache must stay bounded")
}

func TestBasicRegistry_Verify_SaturationIsAnError(t *testing.T) {
	src := basicSourceFor(t)
	reg := NewBasicRegistry(testLogger())
	reg.verifyTimeout = 10 * time.Millisecond

	// Occupy every slot so no compare can start.
	for range cap(reg.sem) {
		reg.sem <- struct{}{}
	}

	_, err := reg.Verify(src, "alice", "hunter2")
	require.ErrorIs(t, err, errBasicSaturated)
}

func TestBasicRegistry_Verify_NoUsersDenies(t *testing.T) {
	reg := NewBasicRegistry(testLogger())

	ok, err := reg.Verify(config.BasicSource{Realm: "empty"}, "alice", "hunter2")
	require.NoError(t, err)
	assert.False(t, ok)
}
