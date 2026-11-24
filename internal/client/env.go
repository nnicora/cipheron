package client

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nnicora/cipheron/internal/secpath"
	"github.com/nnicora/cipheron/peercred"
	"github.com/nnicora/cipheron/wire/transport"
)

// The environment WithEnvironment reads: what the cipheron-sidecar Helm chart sets in the application's container
// (its application environment, cipheron-common.appEnv), every name exactly as the chart writes it.
const (
	// EnvSocket is cipheron's socket, an absolute path. Required.
	EnvSocket = "CIPHERON_SOCKET"
	// EnvServerUID is the uid cipheron runs as, in decimal (WithServerUID). Required. 0 (root), 65534 and the
	// kernel's overflow uid, and 4294967294/4294967295 are refused (peercred.RefusedID), as WithServerUID refuses them.
	EnvServerUID = "CIPHERON_SERVER_UID"
	// EnvRequestKey is the application's request private key file (WithRequestKeyFile). Optional: the chart sets it
	// only when it mounts a key (a socket caller entry may have none). Set, it must not be empty.
	EnvRequestKey = "CIPHERON_REQUEST_KEY"
	// EnvPinsDir is the directory of the profiles' pins: "<profile>.fingerprint" (WithProfileFingerprint) and
	// "<profile>.contextDigest" (WithContextDigestPin: the key-context digests accepted, one per line). Optional: the
	// chart sets it only when it mounts pins. Set, it must not be empty.
	EnvPinsDir = "CIPHERON_PINS_DIR"
	// EnvEnvironment is the deployment's environment, the chart's application.environment. Optional, and UNSET IS
	// PRODUCTION: exactly DevelopmentEnvironment ("development") is development, every other value — "production",
	// "staging", "Development", "dev" — is production, as cipheron's own posture rule reads its configuration's
	// application.environment. In production WithEnvironment never trusts on first use (WithEnvironment). Set, it
	// must not be empty.
	EnvEnvironment = "CIPHERON_ENVIRONMENT"

	// DevelopmentEnvironment is the one value of EnvEnvironment that is not production: the explicit, named opt-out
	// of required pins, for a developer's machine and a development cluster only.
	DevelopmentEnvironment = "development"

	// PinFingerprintSuffix and PinContextDigestSuffix end the names of the files in EnvPinsDir.
	PinFingerprintSuffix   = ".fingerprint"
	PinContextDigestSuffix = ".contextDigest"

	// maxPinFileBytes bounds one fingerprint pin file ("sha256:" and 64 hex digits, and a line end).
	maxPinFileBytes = 256
	// maxContextPinFileBytes bounds one key-context pin file: up to MaxContextDigestPins digests, one per line.
	maxContextPinFileBytes = MaxContextDigestPins * maxPinFileBytes
	// maxPinFiles bounds the entries of the pins directory.
	maxPinFiles = 4096
)

// WithEnvironment configures the client from the environment the cipheron-sidecar Helm chart sets in the
// application's container — and nothing else; no option or constructor ever reads the environment unless it is
// given:
//   - EnvSocket (CIPHERON_SOCKET): the address — pass "" as the address to DialGRPC/DialHTTP;
//   - EnvServerUID (CIPHERON_SERVER_UID): WithServerUID;
//   - EnvRequestKey (CIPHERON_REQUEST_KEY), when set: WithRequestKeyFile;
//   - EnvPinsDir (CIPHERON_PINS_DIR): WithProfileFingerprint for each "<profile>.fingerprint" in it, and
//     WithContextDigestPin for each "<profile>.contextDigest" (one digest per line; more than one while a key-context
//     change rolls out);
//   - EnvEnvironment (CIPHERON_ENVIRONMENT): production unless exactly "development" — and production when unset.
//
// The first two are required, and a variable that is set must not be empty.
//
// IN PRODUCTION A PIN IS REQUIRED (gap review D17): EnvPinsDir must be set — unset is an error, never a silent
// fallback to trust on first use — and WithRequiredPins is implied: a profile the pins directory (or an option) has
// no fingerprint for is refused at its first call with ErrPinRequired, and a pins directory that pins no profile at
// all (with no option pinning one either) refuses the client when it is made, with ErrPinRequired. Only
// CIPHERON_ENVIRONMENT=development (the chart sets it from application.environment) lifts this: there EnvPinsDir is
// optional and, without WithRequiredPins, a profile with no pin is trusted on first use, as before. There is no option
// that lifts it in production: the environment says where the client runs, not the code it runs.
//
// THE PINS DIRECTORY must be absolute. The directory the pin files are READ FROM must be writable by nobody but root
// and this user — not even with the sticky bit, which would still let anyone add a file (a pin of a profile the
// directory does not pin, or a name that is no pin) — and every directory above it too, unless sticky
// (secpath.CheckDirectory with a strict leaf). Which directory that is depends on the layout:
//   - a Kubernetes configMap, secret or projected volume (what the chart mounts): the volume's root holds "..data", a
//     symbolic link to a timestamped directory "..<timestamp>" the kubelet wrote, and links each file to
//     "..data/<name>". The root is the volume's tmpfs root — mode 1777, 3777 with an fsGroup: sticky, writable by
//     everyone — and the pin files are read from the timestamped directory, owned by root and 0755 (2755 with an
//     fsGroup): the strict rule applies to it, and the root is held to the rule for the directories above it
//     (sticky accepted). "..data" must name a "..<name>" entry of the root itself;
//   - any other directory (no "..data" in it): the directory itself.
//
// It holds nothing but "<profile>.fingerprint" and "<profile>.contextDigest" files; each is read through
// secpath.ReadFile (owned by root or this user, writable by nobody else). A ".fingerprint" file is one fingerprint, at
// most 256 bytes. A ".contextDigest" file is one key-context digest per line (blank lines ignored), at most
// MaxContextDigestPins of them, and is ENFORCED (gap review S5): the profile's keys are accepted only when the digest
// cipheron answers is one of them, else ErrContextDigest. A profile the directory has no fingerprint for is refused
// in production (ErrPinRequired); in development it is trusted on first use, unless WithRequiredPins is given; a
// profile with no ".contextDigest" file is not held to a key context.
//
// A directory that cannot be read in full is an error, whatever else pins what — its entries are never read in part
// and the rest taken as absent, which would leave the profiles of the unread files unpinned. A directory that is
// read and holds NO "<profile>.fingerprint" pins nothing (in production, WithRequiredPins is in force):
//   - in development without WithRequiredPins that is accepted: every profile is then trusted on first use, as with
//     EnvPinsDir unset;
//   - with WithRequiredPins and a pin given by an option (WithProfileFingerprint), it is accepted too: the pinned
//     profiles are served, and every other profile's first call fails with ErrPinRequired before anything is asked
//     of cipheron — as for a profile a non-empty directory does not pin;
//   - with WithRequiredPins and NO pin from any source, the client is refused when it is made, with ErrPinRequired
//     (and ErrServerIdentity), the answer every one of its calls would give: no profile could ever be used. That is
//     what a pins mount that came up empty, or the wrong directory, looks like.
//
// THE DIRECTORY IS RE-READ while the client runs (livepins.go; owner decision D-P), every pinsReloadInterval (10
// seconds) — a Kubernetes volume only when its "..data" link moved, which is how the kubelet swaps a ConfigMap's or
// Secret's files, atomically. A read that is whole and that the first read would have accepted becomes the pins in
// force at once — with the options' pins, which the directory can add to and never remove — and keys cached under
// other pins are checked again before their next use: a key-context widen (old and new digest) and narrow (new only)
// need no restart of the application. Never fail-open: an update that cannot be read in full, or holds anything the
// first read refuses (more than MaxContextDigestPins digests for a profile included), is not applied (the pins in
// force stay; it is logged, and WithObserver is told KindPinsReload); a profile whose pin file disappears keeps its
// pins; a fingerprint that changes for a pinned profile is refused (a profile's identity never changes).
//
// What the environment sets may not be set again to something else by another option: an address, WithAnyServer,
// WithServerUID with another uid, WithRequestKey or WithRequestKeyFile with another file when EnvRequestKey is set,
// or another fingerprint for a profile a pin file pins — each is an error, not an override. An option that EQUALS
// the environment's value (WithServerUID of the same uid, WithRequestKeyFile of the same file, WithProfileFingerprint
// of the same fingerprint) is accepted: it says the same thing twice. Options for what the environment leaves unset
// (a request key without EnvRequestKey, pins of other profiles, WithRequiredPins, WithConnections, ...) combine with
// it.
func WithEnvironment() Option {
	return func(o *options) { o.env = true }
}

// fromEnvironment applies WithEnvironment to o, and returns the address the environment names.
func (o *options) fromEnvironment(where string) (string, error) {
	var errs []error
	get := func(name string, required bool) (string, bool) {
		v, ok := os.LookupEnv(name)
		switch {
		case !ok && required:
			errs = append(errs, fmt.Errorf("%s is not set (the cipheron-sidecar chart sets it in the application's container)", name))
		case ok && strings.TrimSpace(v) == "":
			errs = append(errs, fmt.Errorf("%s is set and empty", name))
			ok = false
		}
		return v, ok
	}
	socket, hasSocket := get(EnvSocket, true)
	uid, hasUID := get(EnvServerUID, true)
	key, hasKey := get(EnvRequestKey, false)
	pins, hasPins := get(EnvPinsDir, false)
	env, hasEnv := get(EnvEnvironment, false)
	// Set and empty is refused by get (and read as production meanwhile, never as development).
	production := !hasEnv || env != DevelopmentEnvironment
	if production {
		// Required pins: never trust on first use in production (D17).
		o.requirePins = true
		if !hasPins {
			if _, set := os.LookupEnv(EnvPinsDir); !set {
				errs = append(errs, fmt.Errorf("%w: %s is not set, and the environment is production (%s): a production "+
					"client never trusts a profile's identity on first use — mount the pins (the cipheron-sidecar chart "+
					"does, with %s) or, on a development machine or cluster only, set %s=%s: %w", ErrPinRequired, EnvPinsDir,
					environmentText(env, hasEnv), EnvPinsDir, EnvEnvironment, DevelopmentEnvironment, ErrServerIdentity))
			}
		}
	}

	if where != "" {
		errs = append(errs, fmt.Errorf("an address (%q) and %s are two answers to one question: pass \"\" as the address", where, EnvSocket))
	}
	if hasSocket {
		if !filepath.IsAbs(strings.TrimPrefix(socket, unixScheme)) {
			errs = append(errs, fmt.Errorf("%s=%q: cipheron's socket, an absolute path", EnvSocket, socket))
		}
	}
	if hasUID {
		n, err := strconv.ParseUint(uid, 10, 32)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s=%q: a uid, in decimal", EnvServerUID, uid))
		case peercred.RefusedID(uint32(n), true) != "":
			errs = append(errs, fmt.Errorf("%s=%s is refused: %s", EnvServerUID, uid, peercred.RefusedID(uint32(n), true)))
		case o.anyServer:
			errs = append(errs, fmt.Errorf("%s and WithAnyServer are two answers to one question; pass one", EnvServerUID))
		case o.serverUID != nil && *o.serverUID != uint32(n):
			errs = append(errs, fmt.Errorf("%s=%s and WithServerUID(%d) are two answers to one question; pass one",
				EnvServerUID, uid, *o.serverUID))
		default:
			u := uint32(n)
			o.serverUID = &u
		}
	}
	if hasKey {
		switch {
		case o.requestKey != nil:
			errs = append(errs, fmt.Errorf("%s and WithRequestKey are two answers to one question; pass one", EnvRequestKey))
		case o.requestKeyFile != "" && filepath.Clean(o.requestKeyFile) != filepath.Clean(key):
			errs = append(errs, fmt.Errorf("%s=%s and WithRequestKeyFile(%s) are two answers to one question; pass one",
				EnvRequestKey, key, o.requestKeyFile))
		default:
			o.requestKeyFile = key
		}
	}
	if hasPins {
		if err := o.readPins(pins); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("cipheron: WithEnvironment: %w", errors.Join(errs...))
	}
	return socket, nil
}

// kubeDataLink is the symbolic link, in the root of a Kubernetes configMap, secret or projected volume, to the
// timestamped directory that holds the volume's files (the kubelet's AtomicWriter).
const kubeDataLink = "..data"

// pinsReadDir is the directory the pin files in dir (EnvPinsDir) are read from: dir's "..data" target when dir is
// the root of a Kubernetes volume, dir itself otherwise (WithEnvironment). The target must be a "..<name>" entry of
// dir itself — one name, no "/" — as the kubelet writes it.
func pinsReadDir(dir string) (string, error) {
	target, err := os.Readlink(filepath.Join(dir, kubeDataLink))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return dir, nil
	case err != nil:
		return "", fmt.Errorf("%s %s: %s is not the symbolic link a Kubernetes volume has: %w", EnvPinsDir, dir, kubeDataLink, err)
	case !strings.HasPrefix(target, "..") || strings.ContainsRune(target, '/') || target == ".." || target == kubeDataLink:
		return "", fmt.Errorf("%s %s: %s leads to %q, not to a timestamped directory of the volume itself", EnvPinsDir, dir,
			kubeDataLink, target)
	}
	return filepath.Join(dir, target), nil
}

// dirPins is one complete read of the pins directory (EnvPinsDir): every profile's fingerprint and key-context
// digests as its files say, and the "..data" target the files were read through ("" for a directory that is not a
// Kubernetes volume's root). The fingerprints are not judged here (WithProfileFingerprint judges them when they are
// applied); the key-context files are read one digest per line.
type dirPins struct {
	fingerprints map[string]string
	context      map[string][]string
	target       string
}

// readPinsDir reads every "<profile>.fingerprint" and "<profile>.contextDigest" in dir (EnvPinsDir), from the
// directory pinsReadDir names, which must be writable by nobody but root and this user (a strict leaf), each file
// through the checked reader (secpath.ReadFile). Every failure is returned, joined; what was read beside a failure is
// returned too, for the first read's error report only: a read with an error is never applied by a reload
// (livepins.go).
func readPinsDir(dir string) (dirPins, error) {
	d := dirPins{fingerprints: map[string]string{}, context: map[string][]string{}}
	if !filepath.IsAbs(dir) {
		return d, fmt.Errorf("%s=%q: an absolute path", EnvPinsDir, dir)
	}
	dir = filepath.Clean(dir)
	from, err := pinsReadDir(dir)
	if err != nil {
		return d, err
	}
	if from != dir {
		d.target = filepath.Base(from)
	}
	if err := secpath.CheckDirectory(from, true); err != nil {
		return d, fmt.Errorf("%s %s: the pins are read from %s: %w", EnvPinsDir, dir, from, err)
	}
	names, err := readDirNames(from, maxPinFiles+1)
	if err != nil {
		// Every error: a directory read in part (names and an error) is not a directory read, and the pins of
		// the entries not reached must not be taken as absent.
		return d, fmt.Errorf("%s %s: the pins directory %s could not be read: %w", EnvPinsDir, dir, from, err)
	}
	if len(names) > maxPinFiles {
		return d, fmt.Errorf("%s %s holds more than %d entries", EnvPinsDir, dir, maxPinFiles)
	}
	slices.Sort(names)
	var errs []error
	for _, name := range names {
		if strings.HasPrefix(name, "..") {
			continue // a Kubernetes volume's own entries, when dir is read as it is (..data is followed above)
		}
		profile, isFP := strings.CutSuffix(name, PinFingerprintSuffix)
		digestProfile, isDigest := strings.CutSuffix(name, PinContextDigestSuffix)
		if !isFP && !isDigest {
			errs = append(errs, fmt.Errorf("%s %s: %q is neither <profile>%s nor <profile>%s", EnvPinsDir, dir, name,
				PinFingerprintSuffix, PinContextDigestSuffix))
			continue
		}
		bound := maxPinFileBytes
		if isDigest {
			bound = maxContextPinFileBytes
		}
		raw, err := secpath.ReadFile(filepath.Join(from, name), "cipheron pin", secpath.Public, bound)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		pin := strings.TrimSpace(string(raw))
		switch {
		case isFP && profile == "":
			errs = append(errs, fmt.Errorf("%s %s: %q names no profile", EnvPinsDir, dir, name))
		case isFP:
			d.fingerprints[profile] = pin
		default:
			digests, err := contextDigestLines(dir, name, digestProfile, pin)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			d.context[digestProfile] = digests
		}
	}
	return d, errors.Join(errs...)
}

// readPins applies WithProfileFingerprint for every "<profile>.fingerprint" in dir (EnvPinsDir) and
// WithContextDigestPin for every "<profile>.contextDigest" (readPinsDir), and keeps what it read for the client's
// live re-read of the directory (livepins.go): the directory, the pins the options gave before it was read (inline:
// fixed for the client's life), and this first read.
func (o *options) readPins(dir string) error {
	o.inlinePins, o.inlineContext = maps.Clone(o.pins), cloneContextPins(o.contextPins)
	d, err := readPinsDir(dir)
	errs := append([]error{err}, o.applyDirPins(filepath.Clean(dir), d)...)
	if err == nil {
		o.pinsDir, o.dirPins = filepath.Clean(dir), d
	}
	if o.requirePins && err == nil && len(d.fingerprints) == 0 && len(o.pins) == 0 {
		// No profile is pinned by anything — the directory, or an option (applied before the environment is read) —
		// so every call would fail with ErrPinRequired: say so now, as that same error.
		errs = append(errs, fmt.Errorf("%w (%s %s holds no <profile>%s, and no option pins a profile: no profile can be "+
			"used; the pins were not mounted, or the directory is not the one they are in): %w", ErrPinRequired, EnvPinsDir,
			dir, PinFingerprintSuffix, ErrServerIdentity))
	}
	return errors.Join(errs...)
}

// applyDirPins applies a read of the pins directory dir to o: WithProfileFingerprint per fingerprint (its refusals in
// o.errs, as an option's), WithContextDigestPin per key-context file (its refusals returned, naming the file), in the
// order of the profiles' names.
func (o *options) applyDirPins(dir string, d dirPins) []error {
	for _, profile := range slices.Sorted(maps.Keys(d.fingerprints)) {
		WithProfileFingerprint(profile, d.fingerprints[profile])(o)
	}
	var errs []error
	for _, profile := range slices.Sorted(maps.Keys(d.context)) {
		before := len(o.errs)
		WithContextDigestPin(profile, d.context[profile]...)(o)
		if len(o.errs) > before {
			err := errors.Join(o.errs[before:]...)
			o.errs = o.errs[:before]
			errs = append(errs, fmt.Errorf("%s %s: %s%s: %w", EnvPinsDir, dir, profile, PinContextDigestSuffix, err))
		}
	}
	return errs
}

// contextDigestLines reads the content of profile's ".contextDigest" file name in dir: one key-context digest per line
// (a digest is written as a fingerprint is: transport.ContextDigest), blank lines ignored, at least one.
func contextDigestLines(dir, name, profile, content string) ([]string, error) {
	if profile == "" {
		return nil, fmt.Errorf("%s %s: %q names no profile", EnvPinsDir, dir, name)
	}
	var digests []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !transport.ValidFingerprint(line) {
			return nil, fmt.Errorf("%s %s: %s is not a key-context digest per line (sha256: and 64 lowercase hex digits)",
				EnvPinsDir, dir, name)
		}
		digests = append(digests, line)
	}
	if len(digests) == 0 {
		return nil, fmt.Errorf("%s %s: %s holds no key-context digest", EnvPinsDir, dir, name)
	}
	return digests, nil
}

// cloneContextPins is a copy of m that shares no slice with it (nil stays nil).
func cloneContextPins(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}

// readDirNames reads at most n entry names of dir. A directory with no entry is (nil, nil); any failure — to open
// it, or to read it to the n-th entry or its end — is an error, with no names: a directory read in part is not
// returned as if it were whole. A variable so that a test can make the read fail.
var readDirNames = func(dir string, n int) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(n)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, io.EOF) && len(names) == 0 {
		return nil, nil // an empty directory reads as io.EOF
	}
	if err != nil {
		return nil, err
	}
	return names, nil
}

// environmentText says what EnvEnvironment holds, for an error.
func environmentText(v string, set bool) string {
	if !set {
		return EnvEnvironment + " is unset, which is production"
	}
	return fmt.Sprintf("%s=%q, which is not %q", EnvEnvironment, v, DevelopmentEnvironment)
}
