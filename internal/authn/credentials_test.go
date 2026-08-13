package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ThisIsQasim/token-auth-proxy/internal/config"
)

func TestExtractFrom(t *testing.T) {
	tests := []struct {
		name   string
		loc    config.CredentialLocation
		build  func(r *http.Request)
		want   string
		wantOK bool
	}{
		{
			name: "header exact prefix",
			loc:  config.CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			build: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok123")
			},
			want:   "tok123",
			wantOK: true,
		},
		{
			name: "header lowercase bearer still matches (case-insensitive prefix)",
			loc:  config.CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			build: func(r *http.Request) {
				r.Header.Set("Authorization", "bearer tok123")
			},
			want:   "tok123",
			wantOK: true,
		},
		{
			name: "header missing required prefix",
			loc:  config.CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			build: func(r *http.Request) {
				r.Header.Set("Authorization", "tok123")
			},
			wantOK: false,
		},
		{
			name: "header prefix present but remainder empty",
			loc:  config.CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			build: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
			wantOK: false,
		},
		{
			name:   "header absent",
			loc:    config.CredentialLocation{Location: "header", Name: "Authorization", Prefix: "Bearer "},
			build:  func(r *http.Request) {},
			wantOK: false,
		},
		{
			name: "cookie present, no prefix configured",
			loc:  config.CredentialLocation{Location: "cookie", Name: "session"},
			build: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "session", Value: "tok456"})
			},
			want:   "tok456",
			wantOK: true,
		},
		{
			name:   "cookie absent",
			loc:    config.CredentialLocation{Location: "cookie", Name: "session"},
			build:  func(r *http.Request) {},
			wantOK: false,
		},
		{
			name: "query present",
			loc:  config.CredentialLocation{Location: "query", Name: "token"},
			build: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("token", "tok789")
				r.URL.RawQuery = q.Encode()
			},
			want:   "tok789",
			wantOK: true,
		},
		{
			name:   "query absent",
			loc:    config.CredentialLocation{Location: "query", Name: "token"},
			build:  func(r *http.Request) {},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
			tt.build(r)
			got, ok := extractFrom(r, tt.loc)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	t.Run("ordering: second location wins when first is unpopulated", func(t *testing.T) {
		auth := config.InboundAuthConfig{
			JWT: []config.JWTSource{{
				Name: "a",
				Credentials: []config.CredentialLocation{
					{Location: "header", Name: "Authorization", Prefix: "Bearer "},
					{Location: "cookie", Name: "session"},
				},
			}},
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: "from-cookie"})

		got, ok := extractToken(r, auth)
		require.True(t, ok)
		assert.Equal(t, "from-cookie", got)
	})

	t.Run("ordering: first location wins when both populated", func(t *testing.T) {
		auth := config.InboundAuthConfig{
			JWT: []config.JWTSource{{
				Name: "a",
				Credentials: []config.CredentialLocation{
					{Location: "header", Name: "Authorization", Prefix: "Bearer "},
					{Location: "cookie", Name: "session"},
				},
			}},
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		r.Header.Set("Authorization", "Bearer from-header")
		r.AddCookie(&http.Cookie{Name: "session", Value: "from-cookie"})

		got, ok := extractToken(r, auth)
		require.True(t, ok)
		assert.Equal(t, "from-header", got)
	})

	t.Run("a location that exists but fails its prefix check doesn't stop the search", func(t *testing.T) {
		auth := config.InboundAuthConfig{
			JWT: []config.JWTSource{{
				Name: "a",
				Credentials: []config.CredentialLocation{
					{Location: "header", Name: "Authorization", Prefix: "Bearer "},
					{Location: "cookie", Name: "session"},
				},
			}},
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		r.Header.Set("Authorization", "NotBearer whatever") // present, wrong prefix
		r.AddCookie(&http.Cookie{Name: "session", Value: "from-cookie"})

		got, ok := extractToken(r, auth)
		require.True(t, ok)
		assert.Equal(t, "from-cookie", got)
	})

	t.Run("cross-source: source B's location finds the token", func(t *testing.T) {
		auth := config.InboundAuthConfig{
			JWT: []config.JWTSource{
				{
					Name:        "a",
					Credentials: []config.CredentialLocation{{Location: "header", Name: "Authorization", Prefix: "Bearer "}},
				},
				{
					Name:        "b",
					Credentials: []config.CredentialLocation{{Location: "cookie", Name: "b_session"}},
				},
			},
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		r.AddCookie(&http.Cookie{Name: "b_session", Value: "from-b"})

		got, ok := extractToken(r, auth)
		require.True(t, ok)
		assert.Equal(t, "from-b", got)
	})

	t.Run("disabled source's credentials are never consulted", func(t *testing.T) {
		auth := config.InboundAuthConfig{
			JWT: []config.JWTSource{{
				Name:        "a",
				Disabled:    true,
				Credentials: []config.CredentialLocation{{Location: "cookie", Name: "session"}},
			}},
		}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: "should-not-be-found"})

		_, ok := extractToken(r, auth)
		assert.False(t, ok)
	})

	t.Run("no sources at all", func(t *testing.T) {
		_, ok := extractToken(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil), config.InboundAuthConfig{})
		assert.False(t, ok)
	})
}
