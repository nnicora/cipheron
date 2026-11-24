package client

import (
	"testing"

	"google.golang.org/grpc/connectivity"
)

// stateRPC is a pool member in a given state; nothing is called on it but state.
type stateRPC struct {
	rpc

	s connectivity.State
}

func (r *stateRPC) state() connectivity.State { return r.s }

// TestPickPrefersAUsableConnection: a pool with a broken connection (TransientFailure, Connecting) sends every call
// to the ones that can carry it — Ready, or Idle (it connects at the call) — and, when none can, keeps the
// round-robin (the call waits for its connection). Deep review 2026-11-12, reliability 13.
func TestPickPrefersAUsableConnection(t *testing.T) {
	broken := &stateRPC{s: connectivity.TransientFailure}
	connecting := &stateRPC{s: connectivity.Connecting}
	ready := &stateRPC{s: connectivity.Ready}
	idle := &stateRPC{s: connectivity.Idle}
	c := &Client{rpcs: []rpc{broken, ready, connecting, idle}}
	seen := map[rpc]int{}
	for range 400 {
		seen[c.pick()]++
	}
	if seen[broken] != 0 || seen[connecting] != 0 || seen[ready] == 0 || seen[idle] == 0 {
		t.Fatalf("picked: broken %d, connecting %d, ready %d, idle %d", seen[broken], seen[connecting], seen[ready], seen[idle])
	}
	down := &Client{rpcs: []rpc{&stateRPC{s: connectivity.TransientFailure}, &stateRPC{s: connectivity.TransientFailure}}}
	all := map[rpc]bool{}
	for range 10 {
		all[down.pick()] = true
	}
	if len(all) != 2 {
		t.Fatalf("with no usable connection the round-robin is kept: %d of 2 used", len(all))
	}
}
