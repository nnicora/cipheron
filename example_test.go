//go:build linux || darwin

package cipheron_test

// example_test.go — the package's runnable examples (go doc, pkg.go.dev). Each runs against a fake cipheron on a
// temporary socket (cipherontest: the protocol, cipheron's answers and signatures, and ciphertexts sealed as cipheron
// seals them, under keys the fake makes for the test), so `go test` checks every Output. In production the address is
// cipheron's socket with WithServerUID(10443) (a sidecar) or its network address with WithTLSFiles and
// WithServerSPIFFEID (a service), and the fingerprint is the one `cipheron keygen` printed: ExampleNew_sidecar and
// ExampleNew_network are those two, as a service writes them. WithAnyServer, which the other examples use because the
// fake runs as the test's own user, is for tests only: with it the Client does not authenticate the server.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
)

// exampleTB is the testing.TB the fake needs, for an example (which has none). The fake calls only Helper, Fatal,
// Fatalf and Cleanup: a failure panics, which fails the example, and the cleanups run at close. Any other method is
// the nil embedded interface's, and would panic too.
type exampleTB struct {
	testing.TB

	cleanups []func()
}

func (e *exampleTB) Helper()                      {}
func (e *exampleTB) Fatal(args ...any)            { panic(fmt.Sprint(args...)) }
func (e *exampleTB) Fatalf(f string, args ...any) { panic(fmt.Sprintf(f, args...)) }
func (e *exampleTB) Cleanup(f func())             { e.cleanups = append(e.cleanups, f) }

// exampleCipheron is a fake cipheron serving profiles (shared, until made otherwise) on a temporary socket.
type exampleCipheron struct {
	*cipherontest.Server

	tb     *exampleTB
	socket string
}

func startExample(profiles ...string) *exampleCipheron {
	tb := &exampleTB{}
	fake := cipherontest.New(tb, profiles...)
	return &exampleCipheron{Server: fake, tb: tb, socket: fake.ServeSocket(tb)}
}

// client is a Client of the fake, pinning each profile's fingerprint.
func (e *exampleCipheron) client(profiles ...string) *cipheron.Client {
	opts := []cipheron.Option{cipheron.WithAnyServer()}
	for _, d := range profiles {
		opts = append(opts, cipheron.WithProfileFingerprint(d, e.Fingerprint(d)))
	}
	c, err := cipheron.New(e.socket, opts...)
	if err != nil {
		panic(err)
	}
	e.tb.Cleanup(func() { _ = c.Close() })
	return c
}

func (e *exampleCipheron) close() {
	for i := len(e.tb.cleanups) - 1; i >= 0; i-- {
		e.tb.cleanups[i]()
	}
}

// Encrypt and Decrypt in a shared profile. The ciphertext names the key it was made under (KeyID), which is what a
// service stores beside it, or reads back from it, to find the rows a key migration still has to move.
func Example() {
	srv := startExample("credentials")
	defer srv.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// In production (ExampleNew_sidecar): cipheron.New("/run/cipheron/private/cipheron.sock",
	//	cipheron.WithServerUID(10443), cipheron.WithProfileFingerprint("credentials", "sha256:…"))
	c := srv.client("credentials")

	ct, err := c.Encrypt(ctx, "credentials", []byte("s3cr3t"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	pt, err := c.Decrypt(ctx, "credentials", ct)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	kid, err := cipheron.KeyID(ct)
	if err != nil {
		fmt.Println("key id:", err)
		return
	}
	fmt.Printf("%s, made under %s\n", pt, kid)
	// Output: s3cr3t, made under v1
}

// A sidecar in production, written out (the cipheron-sidecar chart's environment gives the same with
// cipheron.New("", cipheron.WithEnvironment(), cipheron.WithRequiredPins()): see ExampleWithEnvironment). The
// Client is made ONCE, at start-up, shared by the whole process and closed at shutdown — not one per request.
//
// The example is compiled, not run: it needs cipheron on its socket.
func ExampleNew_sidecar() {
	c, err := cipheron.New("/run/cipheron/private/cipheron.sock",
		// The uid cipheron runs as (10443 in its image): any other process on the socket path is refused.
		cipheron.WithServerUID(10443),
		// What `cipheron keygen` printed for the profile. With WithRequiredPins a profile without one is an error.
		cipheron.WithProfileFingerprint("credentials", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		cipheron.WithRequiredPins(),
		// Only when the profile's caller entry has a request key (`cipheron keygen caller` wrote the pair).
		cipheron.WithRequestKeyFile("/etc/app/cipheron/request.key"),
	)
	if err != nil {
		// A configuration error — an option, a file — and none of the package's Err values: fail the start-up.
		fmt.Println("cipheron:", err)
		return
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // every call gets a deadline
	defer cancel()
	ct, err := c.Encrypt(ctx, "credentials", []byte("s3cr3t"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	_ = ct // store it
}

// A service that reaches cipheron over the network, in production: mutual TLS from files (re-read on every
// handshake, so a rotated certificate needs no restart), the server accepted by its SPIFFE ID only, a request key
// — required on the network — and a pin per profile. One Client for the process; Close at shutdown.
//
// The example is compiled, not run: it needs a cipheron to connect to.
func ExampleNew_network() {
	c, err := cipheron.New("cipheron.prod.svc:8443",
		cipheron.WithTLSFiles("/etc/app/tls/tls.crt", "/etc/app/tls/tls.key", "/etc/app/tls/ca.crt"),
		cipheron.WithServerSPIFFEID("spiffe://prod.example.org/cipheron"),
		cipheron.WithRequestKeyFile("/etc/app/cipheron/request.key"),
		cipheron.WithProfileFingerprint("credentials", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		cipheron.WithRequiredPins(),
	)
	if err != nil {
		fmt.Println("cipheron:", err)
		return
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sig, err := c.Sign(ctx, "credentials", []byte("document"))
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	_, _ = sig.Bytes, sig.KeyID // store both
}

// A perTenant WRAPPED profile: the provisioning service creates a tenant's key once and stores the blob with the
// tenant record; every call carries the tenant and its blob. Deleting the tenant's blobs erases its data.
func ExampleClient_Tenant_wrapped() {
	srv := startExample("documents")
	defer srv.close()
	srv.MakePerTenant("documents")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("documents")

	key, err := c.CreateTenantKey(ctx, "documents", "t_acme") // operation provision
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	// store key.Blob with t_acme's record; key.SigningPublicKey verifies its signatures anywhere
	acme := c.Tenant("documents", "t_acme", key.Blob)
	ct, err := acme.Encrypt(ctx, []byte("contract"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	pt, err := acme.Decrypt(ctx, ct)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	kid, err := cipheron.KeyID(ct)
	if err != nil {
		fmt.Println("key id:", err)
		return
	}
	sig, err := acme.Sign(ctx, []byte("contract"))
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	fmt.Println(string(pt))
	fmt.Println("made under the tenant's key:", bytes.Equal(kid.TenantKeyID, key.KeyID))
	fmt.Println("signed by the tenant's key:", cipheron.Verify(key.SigningPublicKey, []byte("contract"), sig.Bytes))
	// Output:
	// contract
	// made under the tenant's key: true
	// signed by the tenant's key: true
}

// A perTenant DERIVED profile: every tenant's keys are derived from the profile's; nothing is stored, a call carries
// the tenant id only. One tenant's ciphertext does not decrypt as another's.
func ExampleClient_Tenant_derived() {
	srv := startExample("customers")
	defer srv.close()
	srv.MakeDerived("customers")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("customers")

	acme, globex := c.Tenant("customers", "t_acme", nil), c.Tenant("customers", "t_globex", nil)
	ct, err := acme.Encrypt(ctx, []byte("acme's profile"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	pt, err := acme.Decrypt(ctx, ct)
	fmt.Printf("%s %v\n", pt, err)
	_, err = globex.Decrypt(ctx, ct)
	fmt.Println("as another tenant:", errors.Is(err, cipheron.ErrInvalidInput))
	// Output:
	// acme's profile <nil>
	// as another tenant: true
}

// Sign through cipheron, verify anywhere: hand the profile's signing keys (Keys) to whoever verifies — they need
// neither cipheron nor a network. Store the signature WITH its key id: after a signing-key rotation the old
// signatures still verify under the key they name — unless the operator revoked that key (a compromise): then
// every signature under it is refused, once the verifier holds a list that says so. Keep the list fresh.
func ExampleVerifyWithKeys() {
	srv := startExample("invoices")
	defer srv.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("invoices")

	doc := []byte("invoice #42: 100 EUR")
	sig, err := c.Sign(ctx, "invoices", doc) // store sig.Bytes and sig.KeyID
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	keys, err := c.Keys(ctx, "invoices") // publish keys.SigningKeys to the verifiers
	if err != nil {
		fmt.Println("keys:", err)
		return
	}

	// Offline, anywhere:
	fmt.Println(cipheron.VerifyWithKeys(keys.SigningKeys, doc, sig.Bytes, sig.KeyID))
	fmt.Println(cipheron.VerifyWithKeys(keys.SigningKeys, []byte("invoice #42: 1000 EUR"), sig.Bytes, sig.KeyID))

	// The operator rotates the signing key and revokes the old one. The next list the verifiers get says so.
	srv.RotateSigning("invoices")
	srv.RevokeSigning("invoices", sig.KeyID)
	if keys, err = c.Keys(ctx, "invoices"); err != nil {
		fmt.Println("keys:", err)
		return
	}
	ok, err := cipheron.VerifyWithKeys(keys.SigningKeys, doc, sig.Bytes, sig.KeyID)
	fmt.Println(ok, errors.Is(err, cipheron.ErrSigningKeyRevoked))
	// Output:
	// true <nil>
	// false <nil>
	// false true
}

// In a derived profile a signature is the profile key's over a message bound to the tenant: it verifies for its
// tenant (VerifyTenantWithKeys, VerifyTenant) and for no other.
func ExampleVerifyTenantWithKeys() {
	srv := startExample("customers")
	defer srv.close()
	srv.MakeDerived("customers")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("customers")

	doc := []byte("consent v3")
	sig, err := c.Tenant("customers", "t_acme", nil).Sign(ctx, doc)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	keys, err := c.Keys(ctx, "customers")
	if err != nil {
		fmt.Println("keys:", err)
		return
	}
	fmt.Println(cipheron.VerifyTenantWithKeys(keys.SigningKeys, "customers", "t_acme", doc, sig.Bytes, sig.KeyID))
	fmt.Println(cipheron.VerifyTenantWithKeys(keys.SigningKeys, "customers", "t_globex", doc, sig.Bytes, sig.KeyID))
	active, _ := keys.Active()
	fmt.Println(cipheron.VerifyTenant(active.PublicKey, "customers", "t_acme", doc, sig.Bytes))
	// Output:
	// true <nil>
	// false <nil>
	// true
}

// A key migration sweep: the configuration made master version v2 the writer; rows made under v1 still decrypt,
// and a background job moves them to v2 with ReEncrypt — the plaintext never leaves cipheron — finding them by
// KeyID, which reads the header locally. Once no row is left under v1, the operator can retire it.
func ExampleKeyID() {
	srv := startExample("credentials")
	defer srv.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("credentials")

	var rows [][]byte // the service's stored ciphertexts
	for _, s := range []string{"alpha", "beta", "gamma"} {
		ct, err := c.Encrypt(ctx, "credentials", []byte(s))
		if err != nil {
			fmt.Println("encrypt:", err)
			return
		}
		rows = append(rows, ct)
	}
	srv.SetWriteVersion("credentials", "v2") // the rollout: v2 listed and active, v1 decryptOnly

	const target = "v2" // the version the configuration now writes under
	moved, current, unreadable := 0, 0, 0
	for i, row := range rows {
		kid, err := cipheron.KeyID(row)
		if err != nil {
			// Not a cipheron ciphertext (ErrInvalidInput): a row the sweep cannot move. COUNT IT AND REPORT IT —
			// a sweep that skips such rows silently reports "done" over data it never looked at, and the operator
			// then retires a key version rows may still need.
			unreadable++
			fmt.Printf("row %d: %v\n", i, err)
			continue
		}
		if kid.MasterVersion == target {
			current++ // already under the target version
			continue
		}
		fresh, err := c.ReEncrypt(ctx, "credentials", row)
		switch {
		case errors.Is(err, cipheron.ErrKeyVersionUnavailable):
			// The row's version is no longer listed: not lost — list the version again, then run the sweep again.
			fmt.Printf("row %d (made under %s): %v\n", i, kid, err)
			return
		case err != nil:
			// Busy, unavailable, a deadline: stop, and run the sweep again later — it resumes where rows remain.
			fmt.Printf("row %d: %v\n", i, err)
			return
		}
		rows[i] = fresh // write back (compare-and-swap on the row in a real store)
		moved++
	}
	fmt.Printf("moved %d, already current %d, unreadable %d\n", moved, current, unreadable)
	// The old version may be retired only when a full pass ends with nothing moved and nothing unreadable.
	for i, row := range rows {
		kid, err := cipheron.KeyID(row)
		if err != nil {
			fmt.Printf("row %d: %v\n", i, err)
			return
		}
		pt, err := c.Decrypt(ctx, "credentials", row)
		if err != nil {
			fmt.Printf("row %d: %v\n", i, err)
			return
		}
		fmt.Println(kid, string(pt))
	}
	// Output:
	// moved 3, already current 0, unreadable 0
	// v2 alpha
	// v2 beta
	// v2 gamma
}

// A call's error is one of the package's values (or its own context's error): test with errors.Is, never the
// message. What the service does next depends on which — next is the order to test them in, the more specific
// value before the one it is a kind of.
func next(err error) string {
	switch {
	case err == nil:
		return "done"
	// Verify could not refresh a key list older than WithKeysMaxAge: nothing was verified. Before ErrUnavailable,
	// which it may also be (the refresh's own error), unless the refresh met an impostor.
	case errors.Is(err, cipheron.ErrKeysStale) && !errors.Is(err, cipheron.ErrServerIdentity):
		return "stale key list: nothing verified; verify again once cipheron is reachable"
	// cipheron cannot serve now.
	case errors.Is(err, cipheron.ErrBusy): // before ErrUnavailable, which it also is
		wait, ok := cipheron.RetryAfter(err)
		if !ok || wait > 5*time.Second { // the delay is the server's word: bound it
			wait = 5 * time.Second
		}
		return fmt.Sprintf("busy: retry after %s", wait)
	case errors.Is(err, cipheron.ErrNoWriter): // before ErrUnavailable
		return "no writer: reads work; retry the write on another replica, or later"
	case errors.Is(err, cipheron.ErrUnavailable):
		return "unavailable: retry with a backoff"
	// Who answered could not be shown to be the profile's cipheron: never retried blindly.
	case errors.Is(err, cipheron.ErrPinRequired): // before ErrServerIdentity, which it also is
		return "no pin for the profile: fix this application's configuration"
	case errors.Is(err, cipheron.ErrServerKeyChanged): // before ErrServerIdentity
		return "the profile's identity changed: stop, and page an operator"
	case errors.Is(err, cipheron.ErrServerIdentity):
		return "not the profile's cipheron: stop, and alert"
	// A signature under a key the profile revoked: never accepted, whatever the bytes.
	case errors.Is(err, cipheron.ErrSigningKeyRevoked):
		return "revoked signing key: reject the signature; re-sign what must stay verifiable"
	// A call the server does not have: retrying does not help.
	case errors.Is(err, cipheron.ErrUnsupported):
		return "unsupported: the server does not have the call; do not retry"
	// The call cannot succeed as it is.
	case errors.Is(err, cipheron.ErrKeyVersionUnavailable):
		return "key version unavailable: nothing is lost; list the version again"
	case errors.Is(err, cipheron.ErrTenancy), errors.Is(err, cipheron.ErrInvalidInput), errors.Is(err, cipheron.ErrTooLarge):
		return "refused for what it is: do not retry"
	case errors.Is(err, cipheron.ErrPermissionDenied):
		return "permission denied: not until cipheron's configuration changes"
	// This process.
	case errors.Is(err, cipheron.ErrClosed):
		return "the Client is closed: make a new one"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "the call's context ended: the caller decides"
	default: // ErrInternal, ErrBadResponse, and anything this version does not know
		return "unexpected: report it"
	}
}

// The errors a service must treat differently, each as cipheron (here: the fake) really answers it.
func Example_errors() {
	srv := startExample("credentials", "documents", "invoices")
	defer srv.close()
	srv.MakePerTenant("documents")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := srv.client("credentials", "documents")

	old, err := c.Encrypt(ctx, "credentials", []byte("made under v1"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}

	// A profile this process may not use — or that does not exist: the same answer.
	_, err = c.Encrypt(ctx, "payroll", []byte("x"))
	fmt.Println("permission denied:", errors.Is(err, cipheron.ErrPermissionDenied))

	// Bytes that are not a cipheron ciphertext, refused before the operation is sent.
	_, err = c.Decrypt(ctx, "credentials", []byte("not a ciphertext"))
	fmt.Println("invalid input:", errors.Is(err, cipheron.ErrInvalidInput))

	// The shared calls in a perTenant profile, refused before the operation is sent.
	_, err = c.Encrypt(ctx, "documents", []byte("x"))
	fmt.Println("tenancy:", errors.Is(err, cipheron.ErrTenancy))

	// cipheron at a limit of requests in flight: busy, with the delay it asks for. It is also ErrUnavailable.
	srv.Fail(cipherontest.Busy)
	_, err = c.Encrypt(ctx, "credentials", []byte("x"))
	wait, _ := cipheron.RetryAfter(err)
	fmt.Println("busy:", errors.Is(err, cipheron.ErrBusy), errors.Is(err, cipheron.ErrUnavailable), wait)
	fmt.Println(" ->", next(err))

	// No master key version writes at this cipheron's clock: a write fails, a read does not.
	srv.Fail(cipherontest.NoWriter)
	_, err = c.Encrypt(ctx, "credentials", []byte("x"))
	_, readErr := c.Decrypt(ctx, "credentials", old)
	fmt.Println("no writer:", errors.Is(err, cipheron.ErrNoWriter), errors.Is(err, cipheron.ErrUnavailable), "and a read:", readErr)
	fmt.Println(" ->", next(err))
	srv.Fail(cipherontest.NoFault)

	// A ciphertext made under a master version cipheron no longer lists: not corruption — list it again.
	srv.SetWriteVersion("credentials", "v2")
	srv.RetireVersion("credentials", "v1")
	_, err = c.Decrypt(ctx, "credentials", old)
	kid, _ := cipheron.KeyID(old) // old was returned by Encrypt above: it parses
	fmt.Println("key version unavailable:", errors.Is(err, cipheron.ErrKeyVersionUnavailable), kid.MasterVersion)
	fmt.Println("and not invalid input:", !errors.Is(err, cipheron.ErrInvalidInput))

	// A signature under a signing key the operator revoked: refused, whatever the bytes — never a bare false.
	doc := []byte("invoice #7")
	sig, err := c.Sign(ctx, "invoices", doc)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	srv.RotateSigning("invoices")
	srv.RevokeSigning("invoices", sig.KeyID)
	_, _ = c.Keys(ctx, "invoices") // what WithKeysMaxAge does by itself, at most 5 minutes later
	ok, err := c.Verify(ctx, "invoices", doc, sig.Bytes, sig.KeyID)
	fmt.Println("signing key revoked:", ok, errors.Is(err, cipheron.ErrSigningKeyRevoked))
	fmt.Println(" ->", next(err))

	// The key list is older than WithKeysMaxAge and cipheron cannot be asked for a new one: Verify fails closed.
	aged, err := cipheron.New(srv.socket, cipheron.WithAnyServer(), cipheron.WithKeysMaxAge(5*time.Second))
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = aged.Close() }()
	sig, err = aged.Sign(ctx, "invoices", doc)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	srv.FailPublicKey(cipherontest.Internal)
	time.Sleep(5*time.Second + 200*time.Millisecond) // WithKeysMaxAge's floor
	ok, err = aged.Verify(ctx, "invoices", doc, sig.Bytes, sig.KeyID)
	srv.FailPublicKey(cipherontest.NoFault)
	fmt.Println("keys stale:", ok, errors.Is(err, cipheron.ErrKeysStale))
	fmt.Println(" ->", next(err))

	// A call the server does not have at all: ErrUnsupported.
	srv.Fail(cipherontest.Unimplemented)
	_, err = c.Encrypt(ctx, "credentials", []byte("x"))
	srv.Fail(cipherontest.NoFault)
	fmt.Println("unsupported:", errors.Is(err, cipheron.ErrUnsupported))
	fmt.Println(" ->", next(err))

	// The server's identity. Test the two specific cases first: both are ErrServerIdentity too.
	// A Client that requires pins, and a profile it has none for: nothing is asked of cipheron.
	strict, err := cipheron.New(srv.socket, cipheron.WithAnyServer(), cipheron.WithRequiredPins(),
		cipheron.WithProfileFingerprint("credentials", srv.Fingerprint("credentials")))
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = strict.Close() }()
	_, err = strict.Encrypt(ctx, "invoices", []byte("x"))
	fmt.Println("pin required:", errors.Is(err, cipheron.ErrPinRequired), errors.Is(err, cipheron.ErrServerIdentity))
	fmt.Println(" ->", next(err))
	// Something answers for the profile with another identity than the pinned one (here the profile was re-created).
	srv.Rekey("credentials")
	_, err = c.Encrypt(ctx, "credentials", []byte("x"))
	fmt.Println("identity changed:", errors.Is(err, cipheron.ErrServerKeyChanged), errors.Is(err, cipheron.ErrServerIdentity))
	fmt.Println(" ->", next(err))

	// The call's own deadline: the context's error, bare — cipheron did not answer in time.
	release := srv.HoldPublicKey() // cipheron is slow
	slow, err := cipheron.New(srv.socket, cipheron.WithAnyServer())
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = slow.Close() }()
	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = slow.Encrypt(short, "invoices", []byte("x"))
	stop()
	release()
	fmt.Println("deadline:", err == context.DeadlineExceeded) //nolint:errorlint // the context's error, bare: identity is what this shows
	fmt.Println(" ->", next(err))

	// A closed Client: nothing is sent.
	_ = c.Close()
	_, err = c.Encrypt(ctx, "credentials", []byte("x"))
	fmt.Println("closed:", errors.Is(err, cipheron.ErrClosed))
	fmt.Println(" ->", next(err))
	// Output:
	// permission denied: true
	// invalid input: true
	// tenancy: true
	// busy: true true 1s
	//  -> busy: retry after 1s
	// no writer: true true and a read: <nil>
	//  -> no writer: reads work; retry the write on another replica, or later
	// key version unavailable: true v1
	// and not invalid input: true
	// signing key revoked: false true
	//  -> revoked signing key: reject the signature; re-sign what must stay verifiable
	// keys stale: false true
	//  -> stale key list: nothing verified; verify again once cipheron is reachable
	// unsupported: true
	//  -> unsupported: the server does not have the call; do not retry
	// pin required: true true
	//  -> no pin for the profile: fix this application's configuration
	// identity changed: true true
	//  -> the profile's identity changed: stop, and page an operator
	// deadline: true
	//  -> the call's context ended: the caller decides
	// closed: true
	//  -> the Client is closed: make a new one
}

// A sidecar the cipheron-sidecar Helm chart installed: the chart sets CIPHERON_SOCKET, CIPHERON_SERVER_UID,
// CIPHERON_REQUEST_KEY (when the application has a request key) and CIPHERON_PINS_DIR (a directory of
// "<profile>.fingerprint" files) in the application's container, and WithEnvironment — never implied — reads exactly
// those. Here the example sets them as the chart would, for the fake cipheron: its socket, this process's uid (the
// fake runs as the test; cipheron's image runs as 10443) and the profile's pin.
func ExampleWithEnvironment() {
	srv := startExample("credentials")
	defer srv.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pins, err := os.MkdirTemp("", "pins")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(pins) }()
	pin := filepath.Join(pins, "credentials"+cipheron.PinFingerprintSuffix)
	if err := os.WriteFile(pin, []byte(srv.Fingerprint("credentials")+"\n"), 0o444); err != nil {
		panic(err)
	}
	for name, value := range map[string]string{
		cipheron.EnvSocket:    srv.socket,                // /run/cipheron/private/cipheron.sock in a pod
		cipheron.EnvServerUID: strconv.Itoa(os.Getuid()), // 10443 in a pod
		cipheron.EnvPinsDir:   pins,                      // /etc/cipheron-client/pins in a pod
	} {
		_ = os.Setenv(name, value)
		defer func() { _ = os.Unsetenv(name) }()
	}

	c, err := cipheron.New("", cipheron.WithEnvironment())
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = c.Close() }()
	ct, err := c.Encrypt(ctx, "credentials", []byte("s3cr3t"))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	pt, err := c.Decrypt(ctx, "credentials", ct)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	fmt.Println(string(pt))
	// Output: s3cr3t
}
