//go:build linux || darwin

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

const (
	fpA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fpB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// sidecarEnv is the environment the sidecar chart sets, over files in a fresh directory: a request key, and a pins
// directory laid out as a Kubernetes projected volume lays it out (each key a link into ..data, a link to a
// timestamped directory).
type sidecarEnv struct {
	dir, keyFile, pinsDir string
	key                   ed25519.PrivateKey
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func newSidecarEnv(t *testing.T, pins map[string]string) *sidecarEnv {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _, err := transport.MarshalRequestKeys(priv)
	if err != nil {
		t.Fatal(err)
	}
	e := &sidecarEnv{dir: dir, keyFile: filepath.Join(dir, "request.key"), pinsDir: filepath.Join(dir, "pins"), key: priv}
	writeFile(t, e.keyFile, string(privPEM), 0o440)
	data := filepath.Join(e.pinsDir, "..2026_11_10_00_00_00.000000001")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(data), filepath.Join(e.pinsDir, "..data")); err != nil {
		t.Fatal(err)
	}
	for name, content := range pins {
		writeFile(t, filepath.Join(data, name), content, 0o444)
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(e.pinsDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(EnvSocket, "/run/cipheron/private/cipheron.sock")
	t.Setenv(EnvServerUID, "10443")
	t.Setenv(EnvRequestKey, e.keyFile)
	t.Setenv(EnvPinsDir, e.pinsDir)
	return e
}

// unsetenv unsets name for the rest of the test (t.Setenv first, so that it is restored).
func unsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

// TestWithEnvironmentReadsTheSidecarChartsEnvironment: every variable is applied as the option it stands for —
// the socket, the server uid, the request key file, a fingerprint per "<profile>.fingerprint" pin and the key-context
// digests of a ".contextDigest" pin (gap review S5: applied, not only checked) — through a pins directory laid out
// as Kubernetes lays out a projected volume.
func TestWithEnvironmentReadsTheSidecarChartsEnvironment(t *testing.T) {
	e := newSidecarEnv(t, map[string]string{"a.fingerprint": fpA + "\n", "a.contextDigest": fpB + "\n", "b.fingerprint": fpB})
	p, err := resolve("", []Option{WithEnvironment()})
	if err != nil {
		t.Fatal(err)
	}
	if p.socket != "/run/cipheron/private/cipheron.sock" || p.serverUID == nil || *p.serverUID != 10443 {
		t.Fatalf("socket %q uid %v", p.socket, p.serverUID)
	}
	if !e.key.Equal(p.requestKey) {
		t.Fatal("the request key is not the file's")
	}
	if len(p.pins) != 2 || p.pins["a"] != fpA || p.pins["b"] != fpB {
		t.Fatalf("pins = %v", p.pins)
	}
	if len(p.contextPins) != 1 || !slices.Equal(p.contextPins["a"], []string{fpB}) {
		t.Fatalf("context pins = %v", p.contextPins)
	}

	// The optional ones may be absent: no key, no pins — in DEVELOPMENT only (production requires the pins:
	// TestWithEnvironmentRequiresPinsInProduction).
	t.Setenv(EnvEnvironment, DevelopmentEnvironment)
	unsetenv(t, EnvRequestKey)
	unsetenv(t, EnvPinsDir)
	if p, err = resolve("", []Option{WithEnvironment()}); err != nil || p.requestKey != nil || len(p.pins) != 0 {
		t.Fatalf("without the optional variables: %+v %v", p, err)
	}
	// unix:// is a socket too.
	t.Setenv(EnvSocket, "unix:///run/cipheron/private/cipheron.sock")
	if p, err = resolve("", []Option{WithEnvironment()}); err != nil || p.socket != "/run/cipheron/private/cipheron.sock" {
		t.Fatalf("a unix:// socket: %+v %v", p, err)
	}
}

// TestWithEnvironmentIsNeverImplicit: with the chart's environment set, a client made without WithEnvironment
// reads none of it — no address, no server uid.
func TestWithEnvironmentIsNeverImplicit(t *testing.T) {
	newSidecarEnv(t, map[string]string{"a.fingerprint": fpA})
	if _, err := resolve("", nil); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("an empty address without WithEnvironment: %v", err)
	}
	if _, err := resolve("/run/cipheron/private/cipheron.sock", nil); err == nil || !strings.Contains(err.Error(), "WithServerUID") {
		t.Fatalf("a socket without WithEnvironment took the uid from somewhere: %v", err)
	}
	p, err := resolve("/run/cipheron/private/cipheron.sock", []Option{WithAnyServer()})
	if err != nil || p.requestKey != nil || len(p.pins) != 0 {
		t.Fatalf("without WithEnvironment: %+v %v", p, err)
	}
}

// TestWithEnvironmentRefuses: a required variable missing, a variable set and empty, a value of the wrong form, a
// pin file that is not one, and every option that sets again what the environment set.
func TestWithEnvironmentRefuses(t *testing.T) {
	type tc struct {
		name  string
		setup func(e *sidecarEnv)
		opts  []Option
		where string
		want  string
	}
	cases := []tc{
		{"no socket", func(*sidecarEnv) { unsetenv(t, EnvSocket) }, nil, "", EnvSocket + " is not set"},
		{"no server uid", func(*sidecarEnv) { unsetenv(t, EnvServerUID) }, nil, "", EnvServerUID + " is not set"},
		{"an empty request key", func(*sidecarEnv) { t.Setenv(EnvRequestKey, "") }, nil, "", EnvRequestKey + " is set and empty"},
		{"an empty pins directory variable", func(*sidecarEnv) { t.Setenv(EnvPinsDir, " ") }, nil, "", EnvPinsDir + " is set and empty"},
		{"a server uid that is not a number", func(*sidecarEnv) { t.Setenv(EnvServerUID, "cipheron") }, nil, "", "a uid, in decimal"},
		{"a server uid beyond 32 bits", func(*sidecarEnv) { t.Setenv(EnvServerUID, "4294967296") }, nil, "", "a uid, in decimal"},
		{"a relative socket", func(*sidecarEnv) { t.Setenv(EnvSocket, "cipheron.sock") }, nil, "", "absolute path"},
		{"a network address as the socket", func(*sidecarEnv) { t.Setenv(EnvSocket, "cipheron:8443") }, nil, "", "absolute path"},
		{"a relative pins directory", func(*sidecarEnv) { t.Setenv(EnvPinsDir, "pins") }, nil, "", "absolute path"},
		{"a missing pins directory", func(e *sidecarEnv) { t.Setenv(EnvPinsDir, filepath.Join(e.dir, "none")) }, nil, "", EnvPinsDir},
		{"a missing request key file", func(e *sidecarEnv) { t.Setenv(EnvRequestKey, filepath.Join(e.dir, "none")) }, nil, "", "request key"},
		{"a pins directory others can write", func(e *sidecarEnv) {
			if err := os.Chmod(e.pinsDir, 0o777); err != nil {
				t.Fatal(err)
			}
		}, nil, "", "unsafe path"},
		{"a pin that is not a fingerprint", func(e *sidecarEnv) { addPin(t, e, "c.fingerprint", "sha256:nope", 0o444) }, nil, "", "not a fingerprint"},
		{"a digest that is not one", func(e *sidecarEnv) { addPin(t, e, "c.contextDigest", "md5:x", 0o444) }, nil, "", "not a key-context digest"},
		{"a pin naming no profile", func(e *sidecarEnv) { addPin(t, e, ".fingerprint", fpA, 0o444) }, nil, "", "names no profile"},
		{"a file that is no pin", func(e *sidecarEnv) { addPin(t, e, "notes.txt", "hello", 0o444) }, nil, "", "neither"},
		{"a pin others can write", func(e *sidecarEnv) { addPin(t, e, "c.fingerprint", fpA, 0o666) }, nil, "", "writable"},
		{"a pin file too long", func(e *sidecarEnv) { addPin(t, e, "c.fingerprint", strings.Repeat(" ", 300)+fpA, 0o444) }, nil, "", "larger than"},
		{"an address and the environment", nil, nil, "/run/other.sock", "two answers"},
		{"a network address and the environment", nil, nil, "cipheron:8443", "two answers"},
		{"WithServerUID of another uid and the environment", nil, []Option{WithServerUID(10444)}, "", "two answers"},
		{"a server uid of root", func(*sidecarEnv) { t.Setenv(EnvServerUID, "0") }, nil, "", EnvServerUID + "=0 is refused"},
		{"the overflow server uid", func(*sidecarEnv) { t.Setenv(EnvServerUID, "65534") }, nil, "", "overflow id"},
		{"server uid (uid_t)-2", func(*sidecarEnv) { t.Setenv(EnvServerUID, "4294967294") }, nil, "", "(uid_t)-2"},
		{"server uid (uid_t)-1", func(*sidecarEnv) { t.Setenv(EnvServerUID, "4294967295") }, nil, "", "(uid_t)-1"},
		{"WithAnyServer and the environment", nil, []Option{WithAnyServer()}, "", "two answers"},
		{"WithRequestKeyFile and the environment's key", nil, []Option{WithRequestKeyFile("/k")}, "", "two answers"},
		{"WithRequestKey and the environment's key", nil, nil, "", "two answers"},
		{"another fingerprint for a pinned profile", nil, []Option{WithProfileFingerprint("a", fpB)}, "", "two fingerprints"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSidecarEnv(t, map[string]string{"a.fingerprint": fpA})
			if c.setup != nil {
				c.setup(e)
			}
			opts := append([]Option{WithEnvironment()}, c.opts...)
			if c.name == "WithRequestKey and the environment's key" {
				opts = append(opts, WithRequestKey(e.key))
			}
			_, err := resolve(c.where, opts)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused, but not for %q: %v", c.want, err)
			}
		})
	}
}

// addPin adds a file to the pins volume as the kubelet does: into the timestamped directory "..data" names, linked
// from the volume's root.
func addPin(t *testing.T, e *sidecarEnv, name, content string, mode os.FileMode) {
	t.Helper()
	writeFile(t, filepath.Join(e.pinsDir, "..data", name), content, mode)
	if err := os.Symlink(filepath.Join("..data", name), filepath.Join(e.pinsDir, name)); err != nil {
		t.Fatal(err)
	}
}

// TestWithEnvironmentCombines: options for what the environment leaves unset are kept — the same fingerprint again,
// another profile's pin, a request key when the environment names none.
func TestWithEnvironmentCombines(t *testing.T) {
	e := newSidecarEnv(t, map[string]string{"a.fingerprint": fpA})
	unsetenv(t, EnvRequestKey)
	p, err := resolve("", []Option{WithEnvironment(), WithProfileFingerprint("a", fpA), WithProfileFingerprint("z", fpB),
		WithRequestKey(e.key), WithConnections(3)})
	if err != nil {
		t.Fatal(err)
	}
	if p.pins["a"] != fpA || p.pins["z"] != fpB || !e.key.Equal(p.requestKey) || p.connections != 3 {
		t.Fatalf("plan = %+v", p)
	}
}

// TestWithEnvironmentRoundTrip: a client made from the environment alone — the socket of a (fake) cipheron, its
// uid, the profile's fingerprint pin — encrypts and decrypts; with a wrong pin in the directory it is refused
// (ErrServerIdentity).
func TestWithEnvironmentRoundTrip(t *testing.T) {
	const profile = "credentials"
	fake := cipherontest.New(t, profile)
	sock := fake.ServeSocket(t)
	newSidecarEnv(t, map[string]string{profile + PinFingerprintSuffix: fake.Fingerprint(profile) + "\n"})
	t.Setenv(EnvSocket, sock)
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	unsetenv(t, EnvRequestKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := DialGRPC("", WithEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ct, err := c.Encrypt(ctx, profile, []byte("from the environment"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, profile, ct); err != nil || string(pt) != "from the environment" {
		t.Fatalf("Decrypt: %q %v", pt, err)
	}

	newSidecarEnv(t, map[string]string{profile + PinFingerprintSuffix: fpA})
	t.Setenv(EnvSocket, sock)
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	unsetenv(t, EnvRequestKey)
	w, err := DialGRPC("", WithEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if _, err := w.Encrypt(ctx, profile, []byte("x")); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("a wrong pin from the environment: %v", err)
	}
}

// TestWithEnvironmentAcceptsTheSameValueTwice (review finding 7): an option that says what the environment says —
// WithServerUID of the same uid, WithRequestKeyFile of the same file (written another way), WithProfileFingerprint of
// the same fingerprint — is accepted; anything else for those is refused (TestWithEnvironmentRefuses).
func TestWithEnvironmentAcceptsTheSameValueTwice(t *testing.T) {
	e := newSidecarEnv(t, map[string]string{"a.fingerprint": fpA})
	p, err := resolve("", []Option{WithEnvironment(), WithServerUID(10443),
		WithRequestKeyFile(filepath.Join(e.dir, ".", "request.key")), WithProfileFingerprint("a", fpA)})
	if err != nil {
		t.Fatal(err)
	}
	if p.serverUID == nil || *p.serverUID != 10443 || !e.key.Equal(p.requestKey) || p.pins["a"] != fpA {
		t.Fatalf("plan = %+v", p)
	}
	// The options before or after WithEnvironment: the same.
	if _, err := resolve("", []Option{WithServerUID(10443), WithRequestKeyFile(e.keyFile), WithEnvironment()}); err != nil {
		t.Fatal(err)
	}
}

// TestWithServerUIDRefusesIdsThatNameNoOne (review finding 6): the client pins its server to a uid; root, the
// overflow uid and (uid_t)-2/-1 name no one in particular, and are refused as the server refuses them as callers.
func TestWithServerUIDRefusesIdsThatNameNoOne(t *testing.T) {
	for _, uid := range []uint32{0, 65534, 4294967294, 4294967295} {
		if _, err := resolve("/run/cipheron/private/cipheron.sock", []Option{WithServerUID(uid)}); err == nil ||
			!strings.Contains(err.Error(), "is refused") {
			t.Errorf("WithServerUID(%d): %v", uid, err)
		}
	}
	if _, err := resolve("/run/cipheron/private/cipheron.sock", []Option{WithServerUID(10443)}); err != nil {
		t.Fatal(err)
	}
}

// kubeVolume lays out a Kubernetes configMap, secret or projected volume as the kubelet's AtomicWriter does — the
// files in a timestamped directory (tsMode), "..data" linking to it, each file linked "..data/<name>" from the root —
// under a root of rootMode (a projected volume's tmpfs root is 1777: sticky and writable by everyone).
func kubeVolume(t *testing.T, root string, rootMode, tsMode os.FileMode, files map[string]string) {
	t.Helper()
	ts := filepath.Join(root, "..2026_11_10_12_00_00.123456789")
	if err := os.MkdirAll(ts, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		writeFile(t, filepath.Join(ts, name), content, 0o444)
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(ts), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ts, tsMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, rootMode); err != nil {
		t.Fatal(err)
	}
}

// TestThePinsAreReadFromAStrictDirectory (review finding 5): the directory the pins are read from must be writable
// by nobody but root and this user, sticky or not — a sticky directory everyone can write still lets anyone ADD a
// pin. In the chart's real mount (a projected volume) that directory is the timestamped one "..data" names (0755),
// while the volume's root is a tmpfs root, 1777: the root is accepted as a directory above, and a stray file put in
// it is never read.
func TestThePinsAreReadFromAStrictDirectory(t *testing.T) {
	setEnv := func(pins string) {
		t.Setenv(EnvSocket, "/run/cipheron/private/cipheron.sock")
		t.Setenv(EnvServerUID, "10443")
		t.Setenv(EnvPinsDir, pins)
		unsetenv(t, EnvRequestKey)
	}
	base := t.TempDir()

	// The chart's mount: root 1777, the timestamped directory 0755 — accepted, and the pins are the volume's.
	root := filepath.Join(base, "projected")
	kubeVolume(t, root, os.ModeSticky|0o777, 0o755, map[string]string{"a.fingerprint": fpA + "\n", "a.contextDigest": fpB})
	// Anyone can write a 1777 root: what it adds there is not read (neither a pin nor a file that is no pin).
	writeFile(t, filepath.Join(root, "b.fingerprint"), fpB, 0o444)
	writeFile(t, filepath.Join(root, "notes.txt"), "x", 0o444)
	setEnv(root)
	p, err := resolve("", []Option{WithEnvironment()})
	if err != nil {
		t.Fatalf("the chart's projected volume (root 1777, ..data 0755): %v", err)
	}
	if len(p.pins) != 1 || p.pins["a"] != fpA {
		t.Fatalf("pins = %v, want only the volume's", p.pins)
	}

	for name, c := range map[string]struct {
		setup func(dir string)
		want  string
	}{
		"a plain directory everyone can write, sticky": {func(dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, "a.fingerprint"), fpA, 0o444)
			if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
				t.Fatal(err)
			}
		}, "writable by its group or by others"},
		"a timestamped directory its group can write": {func(dir string) {
			kubeVolume(t, dir, os.ModeSticky|0o777, 0o775, map[string]string{"a.fingerprint": fpA})
		}, "writable by its group or by others"},
		"a volume root everyone can write, not sticky": {func(dir string) {
			kubeVolume(t, dir, 0o777, 0o755, map[string]string{"a.fingerprint": fpA})
		}, "without the sticky bit"},
		"..data leading out of the volume": {func(dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../projected/..2026_11_10_12_00_00.123456789", filepath.Join(dir, "..data")); err != nil {
				t.Fatal(err)
			}
		}, "not to a timestamped directory of the volume itself"},
		"..data that is not a link": {func(dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "..data"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "not the symbolic link"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, strings.ReplaceAll(name, " ", "-"))
			c.setup(dir)
			setEnv(dir)
			if _, err := resolve("", []Option{WithEnvironment()}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("accepted, or refused for another reason than %q: %v", c.want, err)
			}
		})
	}

	// A plain directory nobody else can write is read as it is.
	plain := filepath.Join(base, "plain")
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(plain, "a.fingerprint"), fpA, 0o444)
	setEnv(plain)
	if p, err := resolve("", []Option{WithEnvironment()}); err != nil || p.pins["a"] != fpA {
		t.Fatalf("a plain 0755 pins directory: %v %v", p, err)
	}
}

// TestWithRequiredPins (review finding 7): with WithRequiredPins, a profile with a pin is served as before, and a
// profile without one fails with ErrPinRequired — which is also ErrServerIdentity — instead of being trusted on first
// use; without the option the unpinned profile is trusted on first use, as before.
func TestWithRequiredPins(t *testing.T) {
	const pinned, unpinned = "credentials", "other"
	fake := cipherontest.New(t, pinned, unpinned)
	sock := fake.ServeSocket(t)
	newSidecarEnv(t, map[string]string{pinned + PinFingerprintSuffix: fake.Fingerprint(pinned) + "\n"})
	t.Setenv(EnvSocket, sock)
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	unsetenv(t, EnvRequestKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := DialGRPC("", WithEnvironment(), WithRequiredPins())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Encrypt(ctx, pinned, []byte("pinned")); err != nil {
		t.Fatalf("the pinned profile: %v", err)
	}
	_, err = c.Encrypt(ctx, unpinned, []byte("unpinned"))
	if !errors.Is(err, ErrPinRequired) || !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("an unpinned profile with WithRequiredPins: %v", err)
	}
	if !strings.Contains(err.Error(), `profile "other"`) || !strings.Contains(err.Error(), EnvPinsDir) {
		t.Errorf("the error does not say which profile and where its pin goes: %v", err)
	}
	if _, err := c.Keys(ctx, unpinned); !errors.Is(err, ErrPinRequired) {
		t.Fatalf("Keys of an unpinned profile with WithRequiredPins: %v", err)
	}

	// Trust on first use without WithRequiredPins: in DEVELOPMENT only (CIPHERON_ENVIRONMENT=development); in
	// production WithRequiredPins is implied (TestWithEnvironmentRequiresPinsInProduction).
	t.Setenv(EnvEnvironment, DevelopmentEnvironment)
	tofu, err := DialGRPC("", WithEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tofu.Close() }()
	if _, err := tofu.Encrypt(ctx, unpinned, []byte("trusted on first use")); err != nil {
		t.Fatalf("an unpinned profile without WithRequiredPins: %v", err)
	}
}

// TestWithEnvironmentRequiresPinsInProduction (gap review D17): under a production environment — CIPHERON_ENVIRONMENT
// unset, or any value but exactly "development" — WithEnvironment never trusts on first use: no pins directory is an
// error (ErrPinRequired), not a fallback; WithRequiredPins is implied, so a profile the directory does not pin is refused
// at its first call before anything is asked of cipheron. CIPHERON_ENVIRONMENT=development is the one opt-out.
func TestWithEnvironmentRequiresPinsInProduction(t *testing.T) {
	newSidecarEnv(t, map[string]string{"a" + PinFingerprintSuffix: fpA + "\n"})
	unsetenv(t, EnvPinsDir)
	for _, env := range []string{"", "production", "staging", "Development", "dev", " development"} {
		if env == "" {
			unsetenv(t, EnvEnvironment)
		} else {
			t.Setenv(EnvEnvironment, env)
		}
		_, err := resolve("", []Option{WithEnvironment()})
		if !errors.Is(err, ErrPinRequired) || !errors.Is(err, ErrServerIdentity) || !strings.Contains(err.Error(), EnvPinsDir) ||
			!strings.Contains(err.Error(), EnvEnvironment) {
			t.Fatalf("%s=%q and no pins directory: %v; want ErrPinRequired naming %s and %s", EnvEnvironment, env, err,
				EnvPinsDir, EnvEnvironment)
		}
	}
	// Set and empty is refused, never read as development.
	t.Setenv(EnvEnvironment, " ")
	if _, err := resolve("", []Option{WithEnvironment()}); err == nil || !strings.Contains(err.Error(), EnvEnvironment+" is set and empty") {
		t.Fatalf("an empty %s: %v", EnvEnvironment, err)
	}
	// development: the pins are optional, and a profile with none is trusted on first use.
	t.Setenv(EnvEnvironment, DevelopmentEnvironment)
	if p, err := resolve("", []Option{WithEnvironment()}); err != nil || p.requirePins {
		t.Fatalf("development without pins: %+v %v", p, err)
	}

	// Production with a pins directory: WithRequiredPins is in force without being given.
	newSidecarEnv(t, map[string]string{"a" + PinFingerprintSuffix: fpA + "\n"})
	unsetenv(t, EnvEnvironment)
	p, err := resolve("", []Option{WithEnvironment()})
	if err != nil || !p.requirePins || p.pins["a"] != fpA {
		t.Fatalf("production with a pin: %+v %v; want required pins", p, err)
	}

	// End to end: the unpinned profile fails its first call, the pinned one is served.
	const pinned, unpinned = "credentials", "other"
	fake := cipherontest.New(t, pinned, unpinned)
	sock := fake.ServeSocket(t)
	newSidecarEnv(t, map[string]string{pinned + PinFingerprintSuffix: fake.Fingerprint(pinned) + "\n"})
	unsetenv(t, EnvEnvironment)
	t.Setenv(EnvSocket, sock)
	t.Setenv(EnvServerUID, strconv.Itoa(os.Getuid()))
	unsetenv(t, EnvRequestKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := DialGRPC("", WithEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Encrypt(ctx, pinned, []byte("pinned")); err != nil {
		t.Fatalf("the pinned profile in production: %v", err)
	}
	if _, err := c.Encrypt(ctx, unpinned, []byte("x")); !errors.Is(err, ErrPinRequired) {
		t.Fatalf("an unpinned profile in production: %v; want ErrPinRequired (never trusted on first use)", err)
	}
}
