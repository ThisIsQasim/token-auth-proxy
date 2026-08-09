package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkProxy_Forward measures raw request-forwarding throughput and
// allocations for the in-process ReverseProxy. Run locally via
// `make bench` (go test -bench=. -benchmem ./internal/proxy/...); not run
// in CI as a pass/fail gate since benchmark numbers are too noisy on
// shared runners to gate on.
func BenchmarkProxy_Forward(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	source := newFakeSource(b, backend.URL)
	rp := New(source, testLogger(), testTransport())
	srv := httptest.NewServer(rp)
	defer srv.Close()

	client := srv.Client()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				b.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
}
