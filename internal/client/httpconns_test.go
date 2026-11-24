package client

// httpconns_test.go — Wave D (deep review 2026-11-12, P13): an HTTP client opens DefaultHTTPConnections connections
// unless WithConnections says otherwise; a gRPC client keeps DefaultConnections. Both under cipheron's default cap
// of connections per caller.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPConnectionsDefault(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "none.sock") // nothing is dialled until a call
	for _, c := range []struct {
		opts []Option
		want int
	}{{nil, DefaultHTTPConnections}, {[]Option{WithConnections(3)}, 3}, {[]Option{WithConnections(MaxConnections)}, MaxConnections}} {
		cl, err := DialHTTP(sock, append([]Option{WithServerUID(uint32(os.Getuid()))}, c.opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		h, ok := cl.rpcs[0].(*httpRPC)
		if !ok {
			t.Fatalf("an HTTP client's transport: got %T", cl.rpcs[0])
		}
		tr := h.tr
		if tr.MaxConnsPerHost != c.want || tr.MaxIdleConnsPerHost != c.want {
			t.Errorf("HTTP: MaxConnsPerHost %d, MaxIdleConnsPerHost %d; want %d", tr.MaxConnsPerHost, tr.MaxIdleConnsPerHost, c.want)
		}
		_ = cl.Close()
	}
	g, err := DialGRPC(sock, WithServerUID(uint32(os.Getuid())))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if len(g.rpcs) != DefaultConnections {
		t.Errorf("gRPC: %d connections; want %d", len(g.rpcs), DefaultConnections)
	}
	if DefaultHTTPConnections < 1 || DefaultHTTPConnections > MaxConnections || MaxConnections > 32 {
		t.Errorf("DefaultHTTPConnections %d, MaxConnections %d: over cipheron's default of 32 per caller",
			DefaultHTTPConnections, MaxConnections)
	}
}
