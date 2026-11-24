// Package zeroize overwrites buffers that held secret material.
//
// WHY THIS IS A PACKAGE AND NOT A THREE-LINE LOOP EACH TIME. Before it existed the tree
// carried ten separate helpers under five names — zeroBytes, zeroSlice, clearBytes, wipe,
// zeroStringMap — in cascade_cipher.go, secp256k1.go, bootstrap.go, piv.go, quorum.go,
// keygen.go, app.go, remotekey and seal/helpers.go, plus roughly 170 open-coded
// `for i := range b { b[i] = 0 }` loops. Every one of them was correct. The cost was not
// correctness, it was that the codebase had no single place to state what zeroization does
// and does not guarantee, no single place to fix if that ever needs to change, and no way to
// grep for "did this path scrub its buffer" that returns a usable answer.
//
// One of those helpers carried the comment "local helper to avoid import cycle with
// server.go". That is the other reason this lives in pkg/: it depends on nothing, so no
// layer has to choose between reaching for the shared helper and keeping its imports clean.
//
// # What this guarantees, and what it does not
//
// It writes zeroes over the bytes you hand it. That is all, and the limits are worth stating
// because a package with this name invites more confidence than Go can deliver:
//
//   - IT CANNOT REACH COPIES. Go copies freely — an append that grew a slice, a value passed
//     by value, a protobuf marshaller's buffer, an interface box. Zeroing the slice you hold
//     does nothing to a copy made earlier. This is why securemem.Value exists: it owns the
//     one authoritative copy in mmap'd, mlock'd memory rather than chasing heap duplicates.
//   - IT CANNOT ZERO A string. Go strings are immutable and their backing array is shared,
//     so a secret typed as string persists until the GC reclaims it and cannot be scrubbed
//     at all. Change the type; there is no helper that fixes this.
//   - IT DOES NOT DEFEAT A DETERMINED COMPILER. Go's compiler does not currently eliminate
//     these stores for a heap-allocated slice, but the language does not promise that. The
//     KeepAlive below is a guard against the value being collected before the write, not a
//     guarantee the write survives optimisation. C has explicit_bzero for this; Go has no
//     equivalent, and pretending otherwise would be the dishonest part.
//
// Use it for transient buffers on the ordinary heap. For a secret that must live longer than
// one operation, use internal/security/securemem instead — that is a different and
// stronger guarantee, and this package is not a substitute for it.
package zeroize

import "runtime"

// Bytes overwrites every byte of b with zero.
//
// nil-safe and idempotent, so it is safe to `defer zeroize.Bytes(buf)` before buf is
// populated and safe to call twice on the same slice. That matters more than it sounds:
// registering the defer BEFORE the first fallible operation is what covers the error
// returns, and a helper that panicked on nil would push callers into registering it late,
// which is precisely where the leaks were.
func Bytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Keeps b reachable across the loop so the slice cannot be collected — and its backing
	// array reused — while the writes are still in flight. It does not promise the compiler
	// keeps the stores; see the package comment.
	runtime.KeepAlive(b)
}

// All overwrites every buffer it is given, skipping nils.
//
// FOR THE SUPERSEDED-BUFFER PATTERN, which is where the subtlest leaks in this tree have
// been. Crypto helpers that return a fresh slice — MultiplyScalars, AddScalars, Encrypt —
// turn `x = f(x, y)` into an orphaned allocation holding the previous value, unreachable
// from any later wipe. Collecting each superseded slice and passing the lot here is the fix:
//
//	var scratch [][]byte
//	defer func() { zeroize.All(scratch...) }()
//	...
//	prev := acc
//	acc = suite.MultiplyScalars(acc, x)
//	scratch = append(scratch, prev)
//
// Appending the OLD slice, not the new one, is the whole trick — getting that backwards
// wipes the value you are about to use and leaves the secret behind.
func All(bufs ...[]byte) {
	for _, b := range bufs {
		Bytes(b)
	}
}

// Slices overwrites every buffer in a slice of buffers.
//
// The same as All for a [][]byte you already hold, without spreading it at the call site.
// Spreading a large scratch list allocates a fresh backing array for the variadic call,
// which on an error path is exactly when you least want an allocation.
func Slices(bufs [][]byte) {
	for _, b := range bufs {
		Bytes(b)
	}
}
