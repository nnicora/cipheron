package cipheron

import (
	"strings"
	"testing"
)

// TestWithTransport: one transport, gRPC unless given; the same one twice is accepted, two different ones or a value
// that is no Transport are refused by New before anything is read or dialled.
func TestWithTransport(t *testing.T) {
	for _, c := range []struct {
		name string
		opts []Option
		want Transport
		err  string
	}{
		{name: "default", want: TransportGRPC},
		{name: "grpc", opts: []Option{WithTransport(TransportGRPC)}, want: TransportGRPC},
		{name: "http", opts: []Option{WithTransport(TransportHTTP)}, want: TransportHTTP},
		{name: "same twice", opts: []Option{WithTransport(TransportHTTP), WithTransport(TransportHTTP)}, want: TransportHTTP},
		{name: "two", opts: []Option{WithTransport(TransportHTTP), WithTransport(TransportGRPC)}, err: "given twice: http and grpc"},
		{name: "zero", opts: []Option{WithTransport(0)}, err: "WithTransport(Transport(0)): not a transport"},
		{name: "unknown", opts: []Option{WithTransport(7)}, err: "WithTransport(Transport(7)): not a transport"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var o options
			for _, f := range c.opts {
				f(&o)
			}
			got, err := o.transport()
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("transport() = %v, %v; want an error with %q", got, err, c.err)
				}
				if _, err := New("/run/cipheron/private/cipheron.sock", append(c.opts, WithAnyServer())...); err == nil ||
					!strings.Contains(err.Error(), c.err) {
					t.Fatalf("New: %v; want an error with %q", err, c.err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("transport() = %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

// TestIsSocketAddress: New's reading of an address, exported for tools that choose options by it.
func TestIsSocketAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		"/run/cipheron/private/cipheron.sock":        true,
		"unix:///run/cipheron/private/cipheron.sock": true,
		"cipheron.sock":          true,
		"cipheron.prod.svc:8443": false,
	} {
		if got, err := IsSocketAddress(addr); err != nil || got != want {
			t.Errorf("IsSocketAddress(%q) = %v, %v; want %v", addr, got, err, want)
		}
	}
	for _, addr := range []string{"", "unix://relative.sock", "host:0", "host:port"} {
		if _, err := IsSocketAddress(addr); err == nil {
			t.Errorf("IsSocketAddress(%q): no error", addr)
		}
	}
}
