package client

// livepins.go — the client re-reads the pins directory while it runs (ops review 2026-11-13, item 16 / KL-1 / DC-4,
// owner decision D-P: reverses "the pins are fixed for the client's life").
//
// WHAT IS LIVE. The pins directory of WithEnvironment (EnvPinsDir): a "<profile>.contextDigest" file the kubelet
// updates (a configMap, secret or projected volume swaps its "..data" link to a new timestamped directory, atomically)
// reaches the running client within pinsReloadInterval, so a key-context change's widen (old and new digest) and
// narrow (new only) need no rollout of the application. A "<profile>.fingerprint" for a profile the client has no pin
// for is live too (a new profile). Pins given in code (WithProfileFingerprint, WithContextDigestPin) are fixed: they are
// part of every set the directory makes, and the directory can add digests beside them, never take them away.
//
// WHAT IS NEVER DONE (fail closed):
//   - an update that cannot be read in full, or holds anything the first read would have refused (a file that is not
//     a pin, a digest that is not one, more than MaxContextDigestPins digests for a profile, a directory chain others
//     can write), is not applied: the pins in force stay, and the failure is reported (logged once per distinct
//     failure, and the observer is told KindPinsReload with profile "");
//   - a profile whose ".fingerprint" or ".contextDigest" file disappears keeps the pins it had: a pin is never dropped
//     by an update — that would widen a pinned profile to "no pin" — and the observer is told KindPinsReload with the
//     profile, once;
//   - a profile's fingerprint never changes (the profile's identity does not): an update that pins another fingerprint
//     for a profile already pinned is not applied (a profile re-created needs a new client, as before);
//   - keys a profile cached under other pins are checked against the pins in force before they are used again
//     (checkCachedPins): a narrowed context pin refetches the keys, and a replica still answering the old digest is
//     ErrContextDigest — the narrow is enforced, not only stored. Every answer is checked against the pins in force
//     when it arrives too (verifyResponse: its signature covers its replica's context digest), so a narrow holds for a
//     call made on keys cached before it.
//
// WithTenantFingerprint and WithWriterVersionPin pins are not files and stay fixed for the client's life.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	slogctx "github.com/veqryn/slog-context"

	"github.com/nnicora/cipheron/wire/transport"
)

// pinsReloadInterval is how often the client looks at its pins directory. The kubelet propagates a ConfigMap change
// within its sync period (about a minute) plus its cache TTL; a ten-second look adds little to that, and costs one
// readlink per look when the directory is a Kubernetes volume whose "..data" did not move. A variable so that a test
// can make it short.
var pinsReloadInterval = 10 * time.Second

// pinSet is the pins in force: never changed once published (Client.pins), replaced whole.
type pinSet struct {
	fingerprints map[string]string   // profile → fingerprint
	context      map[string][]string // profile → the key-context digests accepted
	writers      map[string][]string // profile → the master versions new data may be made under (WithWriterVersionPin)
}

func (p *pinSet) fingerprint(profile string) (string, bool) {
	if p == nil {
		return "", false
	}
	fp, ok := p.fingerprints[profile]
	return fp, ok
}

func (p *pinSet) contextDigests(profile string) ([]string, bool) {
	if p == nil {
		return nil, false
	}
	ds, ok := p.context[profile]
	return ds, ok
}

func (p *pinSet) writerVersions(profile string) ([]string, bool) {
	if p == nil {
		return nil, false
	}
	vs, ok := p.writers[profile]
	return vs, ok
}

// pinsNow is the pin set in force (an empty one for a Client made without newClient, in tests).
func (c *Client) pinsNow() *pinSet {
	if p := c.pins.Load(); p != nil {
		return p
	}
	return &pinSet{}
}

// checkCachedPins returns the profile's cached keys k when they satisfy the pins in force. The keys carry the pin set
// they were last checked under (Keys.checkedUnder: the set fetchKeys held them to, or the one this check stamped), so a
// call made under unchanged pins costs one pointer comparison — and keys a fetch stored after the pins changed under
// it (the fetch began under an older set) are never taken as checked under the newer one. Keys checked under other
// pins:
//   - a fingerprint pinned since (a profile the directory pins now) that k's identity does not match is
//     ErrServerIdentity — the cached identity is not the pinned one;
//   - a key-context pin k's digest does not satisfy (a narrow) fetches the keys again (load: the answer is held to the
//     pins in force, ErrContextDigest otherwise), and the fetched keys are checked again;
//   - keys that satisfy the pins in force are stored again stamped with them (only when the cache still holds k: a
//     newer store is never undone).
func (c *Client) checkCachedPins(ctx context.Context, profile string, k *Keys) (*Keys, bool, error) {
	pins := c.pinsNow()
	if k.checkedUnder == pins {
		return k, false, nil
	}
	if fp, ok := pins.fingerprint(profile); ok && !transport.MatchesFingerprint(profile, k.id, fp) {
		return nil, false, identityFailure(fmt.Errorf("the identity cached for profile %q is %s, not the pinned %s",
			profile, k.Fingerprint, fp))
	}
	if ds, ok := pins.contextDigests(profile); ok && !slices.Contains(ds, k.ContextDigest) {
		fk, err := c.load(ctx, profile)
		if err != nil {
			return nil, false, err
		}
		if !slices.Contains(ds, fk.ContextDigest) {
			c.refuseContext(profile)
			return nil, false, fmt.Errorf("%w: profile %q holds key-context digest %s; this client pins %s", ErrContextDigest,
				profile, fk.ContextDigest, strings.Join(ds, ", "))
		}
		return fk, true, nil
	}
	stamped := k.clone()
	stamped.checkedUnder = pins
	c.keys.CompareAndSwap(profile, k, stamped)
	return stamped, false, nil
}

// livePins is the pins directory's re-read.
type livePins struct {
	dir           string              // EnvPinsDir, cleaned
	interval      time.Duration       // how often it is looked at (pinsReloadInterval when the Client was made)
	inlinePins    map[string]string   // the options' fingerprints: in every set
	inlineContext map[string][]string // the options' key-context digests: in every set
	inlineWriters map[string][]string // the options' writer pins (WithWriterVersionPin): in every set

	mu          sync.Mutex // one reload at a time; guards what follows
	last        dirPins    // the last read applied, with the profiles kept (fail closed) in it
	lastFailure string     // the last failure reported ("": none), so one failure is reported once
	lastKept    string     // the profiles last reported kept
}

// watchPins re-reads the pins directory every pinsReloadInterval until the Client is closed.
func (c *Client) watchPins() {
	t := time.NewTicker(c.live.interval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			_, _ = c.reloadPins()
		}
	}
}

// reloadPins reads the pins directory again and, when the read is whole and every pin in it valid, makes it the pins
// in force (with the options' pins, and with every profile the directory no longer names kept as it was). It reports
// whether the pins in force changed, and the failure that kept them (reported too: logged and observed).
func (c *Client) reloadPins() (bool, error) {
	l := c.live
	if l == nil {
		return false, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.target != "" {
		// A Kubernetes volume: the kubelet writes a new timestamped directory and swaps "..data" to it, so a target
		// unchanged is content unchanged.
		if t, err := os.Readlink(filepath.Join(l.dir, kubeDataLink)); err == nil && t == l.last.target {
			return false, nil
		}
	}
	next, d, kept, err := l.compute()
	if err != nil {
		c.pinsFailed(l, err)
		return false, err
	}
	if l.lastFailure != "" {
		slogctx.Info(context.Background(), "cipheron client: the pins directory reads again; its pins are in force",
			"dir", l.dir)
		l.lastFailure = ""
	}
	if k := strings.Join(kept, ","); k != l.lastKept {
		l.lastKept = k
		if k != "" {
			slogctx.Warn(context.Background(), "cipheron client: the pins directory no longer names a pinned profile's "+
				"file; the profile keeps its pins (a pin is never dropped by an update; restart the client to drop it)",
				"dir", l.dir, "files", kept)
			told := map[string]bool{}
			for _, file := range kept {
				profile := strings.TrimSuffix(strings.TrimSuffix(file, PinFingerprintSuffix), PinContextDigestSuffix)
				if !told[profile] {
					told[profile] = true
					c.tell(profile, KindPinsReload)
				}
			}
		}
	}
	l.last = d
	prev := c.pins.Swap(next)
	changed := !samePins(prev, next)
	if changed {
		slogctx.Info(context.Background(), "cipheron client: the pins directory changed; its pins are in force",
			"dir", l.dir, "context_pinned_profiles", slices.Sorted(maps.Keys(next.context)))
	}
	return changed, nil
}

// compute is the next pin set from a fresh read of the directory: the read (with the profiles kept), and the profiles
// kept because their files are gone. An error leaves everything as it was.
func (l *livePins) compute() (*pinSet, dirPins, []string, error) {
	d, err := readPinsDir(l.dir)
	if err != nil {
		return nil, d, nil, err
	}
	var kept []string
	for profile, fp := range l.last.fingerprints {
		switch now, ok := d.fingerprints[profile]; {
		case !ok:
			d.fingerprints[profile] = fp
			kept = append(kept, profile+PinFingerprintSuffix)
		case now != fp:
			return nil, d, nil, fmt.Errorf("%s %s: %s%s pins %q, not the fingerprint in force (%s): a profile's identity "+
				"never changes, so the update is not applied (a re-created profile needs a new client)",
				EnvPinsDir, l.dir, profile, PinFingerprintSuffix, now, fp)
		}
	}
	for profile, ds := range l.last.context {
		if _, ok := d.context[profile]; !ok {
			d.context[profile] = ds
			kept = append(kept, profile+PinContextDigestSuffix)
		}
	}
	slices.Sort(kept)
	// The same judgment as the first read: the options' pins first, then the directory's, through the options
	// themselves (WithProfileFingerprint, WithContextDigestPin and their refusals; MaxContextDigestPins per profile).
	o := options{}
	for _, profile := range slices.Sorted(maps.Keys(l.inlinePins)) {
		WithProfileFingerprint(profile, l.inlinePins[profile])(&o)
	}
	for _, profile := range slices.Sorted(maps.Keys(l.inlineContext)) {
		WithContextDigestPin(profile, l.inlineContext[profile]...)(&o)
	}
	errs := append(o.applyDirPins(l.dir, d), o.errs...)
	if err := errors.Join(errs...); err != nil {
		return nil, d, nil, err
	}
	return &pinSet{fingerprints: o.pins, context: o.contextPins, writers: l.inlineWriters}, d, kept, nil
}

// pinsFailed reports an update of the pins directory that was not applied: logged, and the observer told
// KindPinsReload with profile "", once per distinct failure (a failure that lasts is not reported every look).
func (c *Client) pinsFailed(l *livePins, err error) {
	if msg := err.Error(); msg != l.lastFailure {
		l.lastFailure = msg
		slogctx.Warn(context.Background(), "cipheron client: the pins directory's update is not applied; the pins in "+
			"force stay", "dir", l.dir, "error", msg)
		c.tell("", KindPinsReload)
	}
}

// samePins reports whether two pin sets pin the same.
func samePins(a, b *pinSet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return maps.Equal(a.fingerprints, b.fingerprints) &&
		maps.EqualFunc(a.context, b.context, func(x, y []string) bool { return slices.Equal(x, y) }) &&
		maps.EqualFunc(a.writers, b.writers, func(x, y []string) bool { return slices.Equal(x, y) })
}
