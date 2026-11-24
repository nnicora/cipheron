//go:build linux || darwin

package client

// livepins_test.go — ops review 2026-11-13 item 16 / D-P: the pins directory is re-read while the client runs.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
)

// pinsVolume is a pins directory laid out as the kubelet lays out a configMap or projected volume, whose content a
// test replaces as the kubelet does: a new timestamped directory, then "..data" swapped to it by a rename.
type pinsVolume struct {
	root string
	n    int
}

func newPinsVolume(t *testing.T, files map[string]string) *pinsVolume {
	t.Helper()
	v := &pinsVolume{root: filepath.Join(t.TempDir(), "pins")}
	if err := os.MkdirAll(v.root, 0o755); err != nil {
		t.Fatal(err)
	}
	v.swap(t, files)
	return v
}

// swap writes files into a new timestamped directory and points "..data" at it atomically (rename of a new link over
// the old one), as the kubelet's AtomicWriter does; each file's top-level link is made as the kubelet makes it.
func (v *pinsVolume) swap(t *testing.T, files map[string]string) {
	t.Helper()
	v.n++
	ts := "..2026_11_14_00_00_00." + strconv.Itoa(1000+v.n)
	if err := os.Mkdir(filepath.Join(v.root, ts), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		writeFile(t, filepath.Join(v.root, ts, name), content, 0o444)
		link := filepath.Join(v.root, name)
		if _, err := os.Lstat(link); errors.Is(err, os.ErrNotExist) {
			if err := os.Symlink(filepath.Join("..data", name), link); err != nil {
				t.Fatal(err)
			}
		}
	}
	tmp := filepath.Join(v.root, "..data_tmp")
	if err := os.Symlink(ts, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(v.root, "..data")); err != nil {
		t.Fatal(err)
	}
}

// observed records what the observer is told.
type observed struct {
	mu  sync.Mutex
	got []string
}

func (o *observed) f(profile, kind string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, profile+"/"+kind)
}

func (o *observed) count(s string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, g := range o.got {
		if g == s {
			n++
		}
	}
	return n
}

// dialEnvFake is a client of fake over gRPC made WithEnvironment, its pins directory the volume's (production: pins
// required).
func dialEnvFake(t *testing.T, fake *cipherontest.Server, v *pinsVolume, opts ...Option) *Client {
	t.Helper()
	t.Setenv(EnvSocket, fake.ServeSocket(t))
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	t.Setenv(EnvPinsDir, v.root)
	unsetenv(t, EnvRequestKey)
	unsetenv(t, EnvEnvironment)
	c, err := DialGRPC("", append([]Option{WithEnvironment()}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func otherDigest(b byte) string { return "sha256:" + strings.Repeat(fmt.Sprintf("%02x", b), 32) }

// TestThePinsAreReReadOnAnAtomicSwap: a widen (old and new digest), a narrow (new only) and a pin back reach a running
// client through the kubelet's swap of "..data", without a new client; the narrow is enforced on keys already cached.
func TestThePinsAreReReadOnAnAtomicSwap(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	fp, v1 := fake.Fingerprint("docs"), fake.ContextDigest("docs")
	old := otherDigest(0xab)
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": old + "\n"})
	c := dialEnvFake(t, fake, v)

	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("before the widen: %v, want ErrContextDigest", err)
	}
	// Unchanged "..data": nothing is read, nothing changes.
	if changed, err := c.reloadPins(); changed || err != nil {
		t.Fatalf("an unchanged volume: changed %v, %v", changed, err)
	}
	// The widen: old and v1.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": old + "\n" + v1 + "\n"})
	if changed, err := c.reloadPins(); !changed || err != nil {
		t.Fatalf("the widen: changed %v, %v", changed, err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("after the widen: %v", err)
	}
	// The narrow to a digest this replica does not answer: the CACHED keys are refused too.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": old})
	if changed, err := c.reloadPins(); !changed || err != nil {
		t.Fatalf("the narrow: changed %v, %v", changed, err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("after the narrow away from the served digest: %v, want ErrContextDigest", err)
	}
	// The served digest alone: honoured after a re-read.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": v1})
	if _, err := c.reloadPins(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatalf("the served digest after a re-read: %v", err)
	}
}

// TestThePinsWatcherPicksUpASwap: the client's own goroutine re-reads the directory (pinsReloadInterval), and stops
// when the client is closed.
func TestThePinsWatcherPicksUpASwap(t *testing.T) {
	ctx := ctxT(t)
	defer func(d time.Duration) { pinsReloadInterval = d }(pinsReloadInterval)
	pinsReloadInterval = 20 * time.Millisecond
	fake := cipherontest.New(t, "docs")
	fp := fake.Fingerprint("docs")
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": otherDigest(0xab)})
	c := dialEnvFake(t, fake, v)
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("before: %v", err)
	}
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": fake.ContextDigest("docs")})
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := c.Encrypt(ctx, "docs", []byte("p"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the swap never reached the client: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestABadPinsUpdateKeepsThePinsInForce: an update that is not whole or holds a pin the first read refuses is not
// applied; the failure is reported once (the observer, KindPinsReload, profile ""), and a good update applies again.
func TestABadPinsUpdateKeepsThePinsInForce(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	fp, v1 := fake.Fingerprint("docs"), fake.ContextDigest("docs")
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": v1})
	var obs observed
	c := dialEnvFake(t, fake, v, WithObserver(obs.f))
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
	before := c.pinsNow()
	for name, files := range map[string]map[string]string{
		"not a digest":        {"docs.fingerprint": fp, "docs.contextDigest": v1 + "\nmd5:nope"},
		"not a pin file":      {"docs.fingerprint": fp, "docs.contextDigest": v1, "notes.txt": "x"},
		"not a fingerprint":   {"docs.fingerprint": "sha256:x", "docs.contextDigest": v1},
		"another identity":    {"docs.fingerprint": fpA, "docs.contextDigest": v1},
		"an empty digest":     {"docs.fingerprint": fp, "docs.contextDigest": "\n"},
		"a profile with none": {"docs.fingerprint": fp, "docs.contextDigest": v1, ".fingerprint": fpB},
	} {
		v.swap(t, files)
		changed, err := c.reloadPins()
		if changed || err == nil {
			t.Fatalf("%s: changed %v, %v; want refused", name, changed, err)
		}
		if c.pinsNow() != before {
			t.Fatalf("%s: the pins in force changed", name)
		}
		if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
			t.Fatalf("%s: the previous pins no longer serve: %v", name, err)
		}
		// The same failure again is not reported again.
		if _, err := c.reloadPins(); err == nil {
			t.Fatalf("%s: the second look applied it", name)
		}
	}
	if n := obs.count("/" + KindPinsReload); n != 6 {
		t.Fatalf("reported %d times (%v); want once per distinct failure (6)", n, obs.got)
	}
	// A directory others can write is refused as at the first read: the pins in force stay.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": v1})
	ts, err := os.Readlink(filepath.Join(v.root, "..data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(v.root, ts), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := c.reloadPins(); err == nil || c.pinsNow() != before {
		t.Fatalf("a writable directory: %v", err)
	}
	// A good update applies.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": v1 + "\n" + otherDigest(1)})
	if changed, err := c.reloadPins(); !changed || err != nil {
		t.Fatalf("a good update after bad ones: changed %v, %v", changed, err)
	}
}

// TestARemovedPinFileKeepsItsPins: a profile whose files disappear keeps its pins (never "no pin"), reported once
// with the profile; the pins of the other profiles follow the directory.
func TestARemovedPinFileKeepsItsPins(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs", "mail")
	fpD, fpM := fake.Fingerprint("docs"), fake.Fingerprint("mail")
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fpD, "docs.contextDigest": otherDigest(0xab),
		"mail.fingerprint": fpM})
	var obs observed
	c := dialEnvFake(t, fake, v, WithObserver(obs.f))
	// docs's files are gone; mail gets a context pin.
	v.swap(t, map[string]string{"mail.fingerprint": fpM, "mail.contextDigest": fake.ContextDigest("mail")})
	if _, err := c.reloadPins(); err != nil {
		t.Fatal(err)
	}
	if ds, ok := c.pinsNow().contextDigests("docs"); !ok || !slices.Equal(ds, []string{otherDigest(0xab)}) {
		t.Fatalf("docs's context pin after its file disappeared: %v %v", ds, ok)
	}
	if fp, ok := c.pinsNow().fingerprint("docs"); !ok || fp != fpD {
		t.Fatalf("docs's fingerprint after its file disappeared: %q %v", fp, ok)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("docs is still pinned to a context it is not served: %v", err)
	}
	if _, err := c.Encrypt(ctx, "mail", []byte("p")); err != nil {
		t.Fatalf("mail: %v", err)
	}
	if n := obs.count("docs/" + KindPinsReload); n != 1 {
		t.Fatalf("docs reported %d times; want 1 (%v)", n, obs.got)
	}
	// Looking again (a new swap of the same content) reports nothing more.
	v.swap(t, map[string]string{"mail.fingerprint": fpM, "mail.contextDigest": fake.ContextDigest("mail")})
	if _, err := c.reloadPins(); err != nil {
		t.Fatal(err)
	}
	if n := obs.count("docs/" + KindPinsReload); n != 1 {
		t.Fatalf("docs reported %d times after another look; want 1", n)
	}
}

// TestThePinsCapHoldsOnAReRead: more than MaxContextDigestPins digests for a profile — in the file, or with the
// options' own digests — is refused, and the pins in force stay.
func TestThePinsCapHoldsOnAReRead(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	fp, v1 := fake.Fingerprint("docs"), fake.ContextDigest("docs")
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": v1})
	c := dialEnvFake(t, fake, v, WithContextDigestPin("docs", otherDigest(0xee)))
	before := c.pinsNow()
	if ds, _ := before.contextDigests("docs"); len(ds) != 2 {
		t.Fatalf("the option's and the file's digests: %v", ds)
	}
	var lines []string
	for i := range MaxContextDigestPins {
		lines = append(lines, otherDigest(byte(i+1)))
	}
	// Eight in the file, plus the option's: nine.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": strings.Join(lines, "\n")})
	if _, err := c.reloadPins(); err == nil || !strings.Contains(err.Error(), "at most") || c.pinsNow() != before {
		t.Fatalf("nine digests with the option's: %v", err)
	}
	// Seven in the file and the option's: eight, accepted; the option's digest is in every set.
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": strings.Join(lines[:7], "\n")})
	if _, err := c.reloadPins(); err != nil {
		t.Fatal(err)
	}
	if ds, _ := c.pinsNow().contextDigests("docs"); len(ds) != MaxContextDigestPins || !slices.Contains(ds, otherDigest(0xee)) {
		t.Fatalf("eight digests: %v", ds)
	}
}

// TestNoLivePinsWithoutADirectory: a client whose pins are all given in code has nothing to re-read.
func TestNoLivePinsWithoutADirectory(t *testing.T) {
	fake := cipherontest.New(t, "docs")
	c := dialFake(t, fake, false, WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	if c.live != nil {
		t.Fatal("a client without a pins directory re-reads one")
	}
	if changed, err := c.reloadPins(); changed || err != nil {
		t.Fatal(changed, err)
	}
}

// TestWithPinsDirIsLive: a client made without WithEnvironment (a network client's case) reads its pins from
// WithPinsDir and re-reads them as WithEnvironment's; two directories are two answers.
func TestWithPinsDirIsLive(t *testing.T) {
	ctx := ctxT(t)
	fake := cipherontest.New(t, "docs")
	fp := fake.Fingerprint("docs")
	v := newPinsVolume(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": otherDigest(0xab)})
	c := dialFake(t, fake, false, WithPinsDir(v.root), WithRequiredPins())
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); !errors.Is(err, ErrContextDigest) {
		t.Fatalf("before: %v", err)
	}
	v.swap(t, map[string]string{"docs.fingerprint": fp, "docs.contextDigest": fake.ContextDigest("docs")})
	if changed, err := c.reloadPins(); !changed || err != nil {
		t.Fatal(changed, err)
	}
	if _, err := c.Encrypt(ctx, "docs", []byte("p")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(fake.ServeSocket(t), []Option{WithAnyServer(), WithPinsDir(v.root), WithPinsDir("/elsewhere")}); err == nil {
		t.Fatal("two pins directories accepted")
	}
	if _, err := resolve(fake.ServeSocket(t), []Option{WithAnyServer(), WithPinsDir("relative/pins")}); err == nil {
		t.Fatal("a relative pins directory accepted")
	}
}
