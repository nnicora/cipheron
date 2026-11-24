//go:build linux || darwin

package client

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/cipherontest"
)

// TestTheContextDigestPinIsEnforced (gap review S5): a client that pins a profile's key-context digest accepts the
// profile's keys only when cipheron's signed answer names one of the pinned digests; any other answer is
// ErrContextDigest, not ErrServerIdentity, and nothing of it is cached. Before the fix the client read the
// "<profile>.contextDigest" pin for its form and never compared it.
func TestTheContextDigestPinIsEnforced(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	k, err := dialFake(t, fake, false).Keys(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	served := k.ContextDigest
	other := "sha256:" + strings.Repeat("ab", 32)

	c := dialFake(t, fake, false, WithContextDigestPin("docs", other))
	_, err = c.Encrypt(ctx, "docs", []byte("p"))
	if !errors.Is(err, ErrContextDigest) || errors.Is(err, ErrServerIdentity) {
		t.Fatalf("an unpinned key context: %v, want ErrContextDigest", err)
	}
	if !strings.Contains(err.Error(), served) || !strings.Contains(err.Error(), other) {
		t.Fatalf("the refusal does not name the answered and the pinned digests: %v", err)
	}
	if _, cached := c.keys.Load("docs"); cached {
		t.Fatal("keys of an unpinned key context were cached")
	}

	// A rollout: the old digest and the new one, either accepted.
	c = dialFake(t, fake, false, WithContextDigestPin("docs", other, served))
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("a pinned key context among two: %v", err)
	}
	// A profile with no context pin is not held to one.
	c = dialFake(t, fake, false, WithContextDigestPin("elsewhere", other))
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("a profile the context pins do not name: %v", err)
	}
}

// TestWithContextDigestPinRefusesWhatIsNotADigest: the option's own refusals, and the joining of two lists.
func TestWithContextDigestPinRefusesWhatIsNotADigest(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("ab", 32), "sha256:"+strings.Repeat("cd", 32)
	for name, opt := range map[string]Option{
		"no profile":     WithContextDigestPin("", a),
		"no digest":      WithContextDigestPin("docs"),
		"not a digest":   WithContextDigestPin("docs", "md5:x"),
		"upper-case hex": WithContextDigestPin("docs", strings.ToUpper(a)),
		"too many digests": func(o *options) {
			for i := range MaxContextDigestPins + 1 {
				WithContextDigestPin("docs", "sha256:"+strings.Repeat(string("0123456789abcdef"[i%16]), 64))(o)
			}
		},
	} {
		var o options
		opt(&o)
		if len(o.errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	var o options
	WithContextDigestPin("docs", a)(&o)
	WithContextDigestPin("docs", b, a)(&o)
	if len(o.errs) != 0 || !slices.Equal(o.contextPins["docs"], []string{a, b}) {
		t.Fatalf("joined: %v %v", o.contextPins, o.errs)
	}
}

// TestAContextDigestPinFileListsOnePerLine: the pins directory's "<profile>.contextDigest" file is read as one digest
// per line (blank lines ignored); an empty one, or a line that is not a digest, is refused when the client is made.
func TestAContextDigestPinFileListsOnePerLine(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("ab", 32), "sha256:"+strings.Repeat("cd", 32)
	newSidecarEnv(t, map[string]string{"a.fingerprint": fpA, "a.contextDigest": a + "\n\n" + b + "\n"})
	p, err := resolve("", []Option{WithEnvironment()})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.contextPins["a"], []string{a, b}) {
		t.Fatalf("context pins = %v", p.contextPins)
	}
	for name, content := range map[string]string{"empty": "\n", "a line that is not one": a + "\nsha1:x\n"} {
		e := newSidecarEnv(t, map[string]string{"a.fingerprint": fpA})
		addPin(t, e, "a.contextDigest", content, 0o444)
		if _, err := resolve("", []Option{WithEnvironment()}); err == nil || !strings.Contains(err.Error(), "a.contextDigest") {
			t.Errorf("%s: %v, want refused naming the file", name, err)
		}
	}
}
