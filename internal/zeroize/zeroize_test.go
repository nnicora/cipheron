package zeroize

import (
	"bytes"
	"testing"
)

func TestBytesOverwritesEverything(t *testing.T) {
	b := []byte("secret-material-0123456789abcdef")
	Bytes(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("buffer not fully zeroed: %q", b)
	}
}

func TestBytesIsNilSafeAndIdempotent(t *testing.T) {
	// Both properties exist so `defer zeroize.Bytes(buf)` can be registered BEFORE buf is
	// populated — which is what makes it cover the error returns. A helper that panicked on
	// nil would push callers into registering the defer late, which is where the leaks were.
	Bytes(nil)
	Bytes([]byte{})

	b := []byte{1, 2, 3}
	Bytes(b)
	Bytes(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatalf("second call disturbed the result: %v", b)
	}
}

func TestBytesWipesThroughAnAlias(t *testing.T) {
	// The caller and callee routinely hold the same backing array — securemem.New wipes its
	// input, frost passes share slices down. Zeroing through one must be visible through the
	// other, or a "wipe" leaves the secret readable via the other name.
	backing := []byte("aliased-secret-0123456789abcdef!")
	alias := backing[:16]
	Bytes(alias)

	if !bytes.Equal(backing[:16], make([]byte, 16)) {
		t.Error("the aliased prefix was not zeroed")
	}
	if bytes.Equal(backing[16:], make([]byte, 16)) {
		t.Error("zeroing a sub-slice wiped beyond its length — it must touch only what it was given")
	}
}

func TestAllSkipsNilsAndWipesTheRest(t *testing.T) {
	a := []byte{1, 2, 3}
	c := []byte{7, 8, 9}
	All(a, nil, c, []byte{})

	if !bytes.Equal(a, []byte{0, 0, 0}) || !bytes.Equal(c, []byte{0, 0, 0}) {
		t.Fatalf("All left material behind: a=%v c=%v", a, c)
	}
}

func TestAllHandlesTheSupersededBufferPattern(t *testing.T) {
	// The shape this exists for: each step allocates a FRESH slice, orphaning the previous
	// one where no later wipe can reach it. Collecting the old slice before reassignment and
	// wiping the collection is the fix — and appending the OLD one is the part that is easy
	// to get backwards.
	step := func(prev []byte) []byte {
		next := make([]byte, len(prev))
		for i := range next {
			next[i] = prev[i] + 1
		}
		return next
	}

	acc := []byte{1, 1, 1}
	orphans := make([][]byte, 0, 4)
	orphans = append(orphans, acc)
	for range 3 {
		prev := acc
		acc = step(acc)
		if &prev[0] == &acc[0] {
			t.Fatal("fixture is wrong: step must allocate, or there is no orphan to test")
		}
		orphans = append(orphans, prev)
	}

	Slices(orphans[:len(orphans)-1]) // every superseded buffer, not the live one
	for i, o := range orphans[:len(orphans)-1] {
		if !bytes.Equal(o, make([]byte, len(o))) {
			t.Errorf("orphan %d survived: %v", i, o)
		}
	}
	if bytes.Equal(acc, make([]byte, len(acc))) {
		t.Error("the LIVE accumulator was wiped — appending the new slice instead of the old " +
			"one destroys the value in use and leaves the secret behind")
	}
}

func TestSlicesAndAllAgree(t *testing.T) {
	mk := func() [][]byte { return [][]byte{{1, 2}, {3, 4}, {5, 6}} }
	viaAll, viaSlices := mk(), mk()

	All(viaAll...)
	Slices(viaSlices)

	for i := range viaAll {
		if !bytes.Equal(viaAll[i], viaSlices[i]) {
			t.Fatalf("All and Slices disagree at %d: %v vs %v", i, viaAll[i], viaSlices[i])
		}
	}
}
