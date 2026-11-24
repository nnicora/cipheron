//go:build linux || darwin

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/nnicora/cipheron/cipherontest"
)

// TestWithRoundRobinSpreadsOverEveryResolvedAddress (gap review D8): a name that resolves to two replicas (here a
// manual resolver standing in for a headless Service's DNS) gets a verified connection to EACH, and calls are served
// by both; without WithRoundRobin one connection reaches one of them. Every connection is verified as one is (the
// server certificate by the name, the profile's pin).
func TestWithRoundRobinSpreadsOverEveryResolvedAddress(t *testing.T) {
	const profile = "credentials"
	ca := cipherontest.NewCA(t, "ca")
	fake := cipherontest.New(t, profile)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fake.RequireRequestKey(profile, pub)
	var hs [2]atomic.Int64
	addrs := make([]string, 2)
	for i := range addrs {
		addrs[i] = fake.ServeTLSConfig(t, ca.Server(t, ""), ca, func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { hs[i].Add(1); return nil }
		})
	}
	rb := manual.NewBuilderWithScheme("cphtest")
	var state []resolver.Address
	for _, a := range addrs {
		state = append(state, resolver.Address{Addr: a})
	}
	rb.InitialState(resolver.State{Addresses: state})
	saved := roundRobinTarget
	roundRobinTarget = func(address string) (string, []grpc.DialOption) {
		return "cphtest:///" + address, []grpc.DialOption{grpc.WithResolvers(rb)}
	}
	t.Cleanup(func() { roundRobinTarget = saved })

	tc := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/ns/app/sa/app", ca.Pool)
	// "localhost:1": the name the server certificate is verified by; the manual resolver gives the real addresses.
	c, err := DialGRPC("localhost:1", WithTLS(tc), WithRequestKey(priv), WithConnections(1), WithRoundRobin(),
		WithProfileFingerprint(profile, fake.Fingerprint(profile)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for range 8 {
		ct, err := c.Encrypt(ctx, profile, []byte("spread"))
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := c.Decrypt(ctx, profile, ct); err != nil || string(pt) != "spread" {
			t.Fatalf("Decrypt: %q %v", pt, err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for (hs[0].Load() == 0 || hs[1].Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if hs[0].Load() == 0 || hs[1].Load() == 0 {
		t.Fatalf("handshakes per replica %d, %d: round_robin did not connect to every resolved address", hs[0].Load(), hs[1].Load())
	}
}

// TestWithRoundRobinIsNetworkGRPCOnly: a socket address and the HTTP client refuse it.
func TestWithRoundRobinIsNetworkGRPCOnly(t *testing.T) {
	if _, err := DialGRPC("/run/cipheron/private/cipheron.sock", WithAnyServer(), WithRoundRobin()); err == nil ||
		!strings.Contains(err.Error(), "WithRoundRobin") {
		t.Fatalf("a socket with WithRoundRobin: %v", err)
	}
	ca := cipherontest.NewCA(t, "ca")
	tc := cipherontest.ClientTLS(t, ca, "spiffe://prod.example.org/ns/app/sa/app", ca.Pool)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := DialHTTP("localhost:8443", WithTLS(tc), WithRequestKey(priv), WithRoundRobin()); err == nil ||
		!strings.Contains(err.Error(), "WithRoundRobin") {
		t.Fatalf("DialHTTP with WithRoundRobin: %v", err)
	}
}
