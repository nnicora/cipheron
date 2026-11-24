//go:build linux || darwin

package client

// pinalias_test.go — the published pin set is read, never written, by the calls that check answers against it
// (verifyResponse: the pins' slice has spare capacity once three, five or seven digests are pinned, and an append onto
// it would write into the array every concurrent call reads); and what a key fetch returns is held to the pins in force
// when the call returns, not only to the pins the fetch began under (CL-1, the live-pins stamping window, for the calls
// that return or use a fetch's keys directly: Keys, KeyStatement, Verify's refresh).

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
)

// maxContextVersion is the highest master version pinnedAmong lists (v2 … v8: n+1 contexts for n up to 7).
const maxContextVersion = 8

// onContext puts the fake's profile "docs" on the i-th key context of pinnedAmong: master versions v2 … v(i+1) listed
// in order after v1, the rest retired.
func onContext(fake *cipherontest.Server, i int) {
	for v := 2; v <= maxContextVersion; v++ {
		fake.RetireVersion("docs", fmt.Sprintf("v%d", v))
	}
	for v := 2; v <= i+1; v++ {
		fake.ListVersion("docs", fmt.Sprintf("v%d", v))
	}
}

// pinnedAmong is a fake whose profile "docs" has n+1 key contexts (onContext 0 … n, all distinct) and a client pinned to
// the first n of them (WithContextDigestPin: a slice built by append, with spare capacity for n = 3, 5, 7), its keys
// cached on context 0, that has seen context n — a refused fetch: a context the profile's verified keys gave that the
// pins do not name. The fake is back on context 0. It returns the digests in order.
func pinnedAmong(t *testing.T, n int) (*Client, *cipherontest.Server, []string) {
	t.Helper()
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	digests := make([]string, 0, n+1)
	for i := 0; i <= n; i++ {
		onContext(fake, i)
		d := fake.ContextDigest("docs")
		if slices.Contains(digests, d) {
			t.Fatalf("context %d repeats an earlier digest", i)
		}
		digests = append(digests, d)
	}
	onContext(fake, 0)
	if fake.ContextDigest("docs") != digests[0] {
		t.Fatal("the fake is not back on context 0")
	}
	c := dialFake(t, fake, false, WithContextDigestPin("docs", digests[:n]...))
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	onContext(fake, n)
	if _, err := c.Keys(ctx, "docs"); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("a fetch of the unpinned context %d: %v; want ErrContextDigest", n, err)
	}
	onContext(fake, 0)
	if _, err := c.Keys(ctx, "docs"); err != nil {
		t.Fatal(err)
	}
	pins, _ := c.pinsNow().contextDigests("docs")
	if !slices.Equal(pins, digests[:n]) || cap(pins) == len(pins) {
		t.Fatalf("the pins are %q (cap %d): want the first %d digests with spare capacity", pins, cap(pins), n)
	}
	return c, fake, digests
}

// publishedPins is the published pin set and the whole array behind its "docs" digests (up to their capacity), with a
// copy of that array: unchanged reports whether the pin set in force is still the same one, holding the same bytes.
func publishedPins(c *Client) (unchanged func() bool, whole []string) {
	set := c.pinsNow()
	pins, _ := set.contextDigests("docs")
	whole = pins[:cap(pins)]
	before := slices.Clone(whole)
	return func() bool { return c.pinsNow() == set && slices.Equal(whole, before) }, whole
}

// TestAnAnswerNeverWritesThePublishedPins: a client pinned to 3, 5 and 7 key-context digests checks an answer of a
// context no PublicKey answer showed it (ErrServerIdentity) and one of the context the profile gave that the pins do not
// name (ErrContextDigest naming it, the profile marked refused): both refusals are kept, and the published pin set —
// the array behind it included — is exactly what it was.
func TestAnAnswerNeverWritesThePublishedPins(t *testing.T) {
	for _, n := range []int{3, 5, 7} {
		t.Run(fmt.Sprintf("%d pins", n), func(t *testing.T) {
			ctx := ctxT(t)
			c, fake, digests := pinnedAmong(t, n)
			unchanged, whole := publishedPins(c)

			fake.SetMode(cipherontest.AnswerOtherContext)
			ct, err := c.Encrypt(ctx, "docs", []byte("p"))
			fake.SetMode(cipherontest.Honest)
			if ct != nil || !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrContextDigest) {
				t.Fatalf("an answer of a context never shown: %v; want ErrServerIdentity, nothing returned", err)
			}
			if !unchanged() {
				t.Fatalf("after an answer of a context never shown the published pins' array holds %q", whole)
			}

			onContext(fake, n)
			ct, err = c.Encrypt(ctx, "docs", []byte("p"))
			if ct != nil || !errors.Is(err, ErrContextDigest) || !strings.Contains(err.Error(), digests[n]) ||
				!c.contextRefused("docs") {
				t.Fatalf("an answer of the seen, unpinned context: %v (marked %v); want ErrContextDigest naming it, the "+
					"profile marked", err, c.contextRefused("docs"))
			}
			if !unchanged() {
				t.Fatalf("after an answer of the seen, unpinned context the published pins' array holds %q", whole)
			}

			onContext(fake, 0)
			if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
				t.Fatalf("a replica on a pinned context again: %v", err)
			}
			if !unchanged() {
				t.Fatalf("after an honest answer the published pins' array holds %q", whole)
			}
		})
	}
}

// TestConcurrentAnswersOnlyReadThePins (run with -race): concurrent answers of a context the client does not accept,
// checked against 3, 5 and 7 pinned digests while the client has seen another context the pins do not name, each
// refused as ErrServerIdentity on its own — no call writes the pin set every other call reads.
func TestConcurrentAnswersOnlyReadThePins(t *testing.T) {
	for _, n := range []int{3, 5, 7} {
		t.Run(fmt.Sprintf("%d pins", n), func(t *testing.T) {
			ctx := ctxT(t)
			c, fake, _ := pinnedAmong(t, n)
			unchanged, whole := publishedPins(c)
			fake.SetMode(cipherontest.AnswerOtherContext)
			errs := make([]error, 16)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					ct, err := c.Encrypt(ctx, "docs", []byte("p"))
					if ct != nil {
						err = errors.New("a ciphertext was returned")
					}
					errs[i] = err
				})
			}
			wg.Wait()
			fake.SetMode(cipherontest.Honest)
			for i, err := range errs {
				if !errors.Is(err, ErrServerIdentity) || errors.Is(err, ErrContextDigest) {
					t.Errorf("call %d: %v; want ErrServerIdentity", i, err)
				}
			}
			if !unchanged() {
				t.Fatalf("after concurrent answers the published pins' array holds %q", whole)
			}
		})
	}
}

// TestWhatAFetchReturnsIsHeldToThePinsInForce (CL-1, the live-pins stamping window, the calls that return or use a
// fetch's keys directly): Keys, KeyStatement and Verify's refresh of a list older than the maximum age fetch the
// profile's keys under pins {D1, D2}; the fetch is held, the pins narrow to {D1}, and the fetch answers D2. The call
// returns ErrContextDigest naming D2 — never D2's keys, a statement of D2, or a verdict under D2's list — and is
// served again once a replica is back on D1.
func TestWhatAFetchReturnsIsHeldToThePinsInForce(t *testing.T) {
	for _, which := range []string{"Keys", "KeyStatement", "Verify"} {
		t.Run(which, func(t *testing.T) {
			ctx := ctxT(t)
			fake := cipherontest.New(t, "docs")
			d1 := fake.ContextDigest("docs")
			fake.ListVersion("docs", "v2")
			d2 := fake.ContextDigest("docs")
			fake.RetireVersion("docs", "v2")
			c := dialFake(t, fake, false, WithContextDigestPin("docs", d1, d2))
			s := signedBy(t, c, "docs", []byte("d")) // D1's keys cached, checked under {D1, D2}
			call := map[string]func() (string, error){
				"Keys": func() (string, error) {
					k, err := c.Keys(ctx, "docs")
					if err != nil {
						return "", err
					}
					return k.ContextDigest, nil
				},
				"KeyStatement": func() (string, error) {
					st, err := c.KeyStatement(ctx, "docs")
					if err != nil {
						return "", err
					}
					return st.ContextDigest, nil
				},
				"Verify": func() (string, error) {
					ok, err := c.Verify(ctx, "docs", []byte("d"), s.Bytes, s.KeyID)
					if err != nil {
						return "", err
					}
					return fmt.Sprintf("a verdict (%v)", ok), nil
				},
			}[which]
			if which == "Verify" {
				// The list is older than the maximum age from now on: Verify fetches it again before it decides.
				c.now = func() time.Time { return time.Now().Add(2 * DefaultKeysMaxAge) }
			}
			fake.ListVersion("docs", "v2") // the replica moves to D2
			calls := fake.PublicKeyCalls()
			release := fake.HoldPublicKey()
			type result struct {
				got string
				err error
			}
			done := make(chan result, 1)
			go func() {
				got, err := call() // its fetch begins under {D1, D2}
				done <- result{got, err}
			}()
			waitFor(t, func() bool { return fake.PublicKeyCalls() > calls })
			wide := c.pinsNow()
			c.pins.Store(&pinSet{fingerprints: wide.fingerprints, context: map[string][]string{"docs": {d1}}, writers: wide.writers})
			release()
			r := <-done
			if !errors.Is(r.err, ErrContextDigest) || !strings.Contains(r.err.Error(), d2) {
				t.Fatalf("%s whose fetch answered D2 after the pins narrowed to D1: %q, %v; want ErrContextDigest naming D2",
					which, r.got, r.err)
			}
			fake.RetireVersion("docs", "v2") // a replica back on D1
			if r, err := call(); err != nil || (which != "Verify" && r != d1) {
				t.Fatalf("%s on D1 again: %q, %v", which, r, err)
			}
		})
	}
}
