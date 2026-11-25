package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// The fake's server and client identities: the server certificate names serverID (and localhost, 127.0.0.1, ::1),
// the client certificate names clientID.
const (
	serverID = "spiffe://cipheron.test/cipheron"
	clientID = "spiffe://cipheron.test/java-client"
)

// shim is the testing.TB cipherontest asks for, outside `go test`: Helper does nothing, Fatal ends the process with
// the message (the Java test reads it as the harness failing), Cleanup runs at exit. Any other method of
// testing.TB is the nil interface's and panics: cipherontest uses none.
type shim struct {
	testing.TB

	mu       sync.Mutex
	cleanups []func()
}

func (t *shim) Helper() {}

func (t *shim) Fatal(args ...any) { t.die(fmt.Sprint(args...)) }

func (t *shim) Fatalf(format string, args ...any) { t.die(fmt.Sprintf(format, args...)) }

func (t *shim) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "harness fake: "+format+"\n", args...)
}

func (t *shim) Cleanup(f func()) {
	t.mu.Lock()
	t.cleanups = append(t.cleanups, f)
	t.mu.Unlock()
}

func (t *shim) cleanup() {
	t.mu.Lock()
	cs := t.cleanups
	t.cleanups = nil
	t.mu.Unlock()
	for i := len(cs) - 1; i >= 0; i-- {
		cs[i]()
	}
}

func (t *shim) die(msg string) {
	fmt.Fprintln(os.Stderr, "harness fake:", msg)
	t.cleanup()
	os.Exit(2)
}

// ready is the line the fake writes once it serves: where, and what to pin.
type ready struct {
	Socket     string                  `json:"socket"`
	HTTPSocket string                  `json:"httpSocket"`
	TLS        string                  `json:"tls"`
	HTTPTLS    string                  `json:"httpTls"`
	CAFile     string                  `json:"caFile"`
	ClientCert string                  `json:"clientCert"`
	ClientKey  string                  `json:"clientKey"`
	RequestKey string                  `json:"requestKey"`
	ServerID   string                  `json:"serverId"`
	UID        int                     `json:"uid"`
	Profiles   map[string]profileReady `json:"profiles"`
}

type profileReady struct {
	Fingerprint   string `json:"fingerprint"`
	ContextDigest string `json:"contextDigest"`
}

// runFake serves cipherontest's fake for the Java library's integration tests:
//
//	harness fake -profiles ledger,people:derived,docs:wrapped
//
// on a gRPC unix socket, an HTTP unix socket, gRPC over mutual TLS and the JSON API over mutual TLS (both on
// 127.0.0.1), writes one JSON line (ready) on standard output, then reads control commands on standard input, one
// JSON object per line, and answers each with one line ({"ok":...} or {"error":"..."}). It exits when its standard
// input closes.
func runFake(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fake", flag.ContinueOnError)
	profiles := fs.String("profiles", "ledger", "profiles to serve: name[:shared|wrapped|derived], comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tb := &shim{}
	defer tb.cleanup()
	names, kinds, err := parseProfiles(*profiles)
	if err != nil {
		return err
	}
	fake := cipherontest.New(tb, names...)
	for i, n := range names {
		switch kinds[i] {
		case "wrapped":
			fake.MakePerTenant(n)
		case "derived":
			fake.MakeDerived(n)
		}
	}
	dir, err := os.MkdirTemp("", "cph-java")
	if err != nil {
		return err
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	ca := cipherontest.NewCA(tb, "cipheron test CA")
	client := ca.Client(tb, clientID)
	_, requestKeyFile := cipherontest.RequestKey(tb, dir, "request.key")
	// While refuse is set, both TLS listeners refuse every client certificate in the handshake, as cipheron refuses
	// an identity no profile lists: crypto/tls answers the failed VerifyConnection with a bad_certificate alert,
	// which TLS 1.3 sends after the server's Finished (refuseCertificates).
	var refuse atomic.Bool
	verify := func(c *tls.Config) {
		c.VerifyConnection = func(tls.ConnectionState) error {
			if refuse.Load() {
				return errNotListed
			}
			return nil
		}
	}
	leaf := ca.Server(tb, serverID)
	httpTLS, err := serveHTTPTLS(tb, fake, leaf, ca, verify)
	if err != nil {
		return err
	}
	r := ready{
		Socket:     fake.ServeSocket(tb),
		HTTPSocket: fake.ServeHTTPSocket(tb),
		TLS:        fake.ServeTLSConfig(tb, leaf, ca, verify),
		HTTPTLS:    httpTLS,
		CAFile:     cipherontest.Write(tb, dir, "ca.pem", ca.PEM, 0o644),
		ClientCert: cipherontest.Write(tb, dir, "client.pem", client.ChainPEM, 0o644),
		ClientKey:  cipherontest.Write(tb, dir, "client.key", client.KeyPEM, 0o600),
		RequestKey: requestKeyFile,
		ServerID:   serverID,
		UID:        os.Getuid(),
		Profiles:   map[string]profileReady{},
	}
	for _, n := range names {
		r.Profiles[n] = profileReady{Fingerprint: fake.Fingerprint(n), ContextDigest: fake.ContextDigest(n)}
	}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(r); err != nil {
		return err
	}
	return control(ctx, &harness{fake: fake, refuse: &refuse}, out, os.Stdin)
}

var errNotListed = errors.New("no profile lists the identity")

// serveHTTPTLS serves the fake's JSON API over mutual TLS 1.3 on 127.0.0.1, as cipheron's network listener serves
// it to a client that offers ALPN http/1.1: the server presents leaf and requires a client certificate issued by
// clientCA. It returns the address.
func serveHTTPTLS(tb *shim, fake *cipherontest.Server, leaf *cipherontest.Leaf, clientCA *cipherontest.CA,
	configure func(*tls.Config),
) (string, error) {
	pair, err := tls.X509KeyPair(leaf.ChainPEM, leaf.KeyPEM)
	if err != nil {
		return "", err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.Pool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	configure(cfg)
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	hs := &http.Server{Handler: fake.HTTPHandler(tb), TLSConfig: cfg, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.ServeTLS(l, "", "") }()
	tb.Cleanup(func() { _ = hs.Close() })
	return l.Addr().String(), nil
}

// harness is what the control commands act on: the fake, and the TLS listeners' refusal switch.
type harness struct {
	fake   *cipherontest.Server
	refuse *atomic.Bool
}

func parseProfiles(s string) (names, kinds []string, err error) {
	for _, p := range strings.Split(s, ",") {
		name, kind, _ := strings.Cut(strings.TrimSpace(p), ":")
		switch kind {
		case "", "shared":
			kind = "shared"
		case "wrapped", "derived":
		default:
			return nil, nil, fmt.Errorf("profile %q: a tenancy of shared, wrapped or derived", p)
		}
		names, kinds = append(names, name), append(kinds, kind)
	}
	return names, kinds, nil
}

// command is one control line: an operation and its arguments.
type command struct {
	Op      string   `json:"op"`
	Profile string   `json:"profile,omitempty"`
	Tenant  string   `json:"tenant,omitempty"`
	Mode    string   `json:"mode,omitempty"`
	Fault   string   `json:"fault,omitempty"`
	KeyID   string   `json:"keyId,omitempty"`
	Version string   `json:"version,omitempty"`
	PEM     string   `json:"pem,omitempty"`
	Ops     []string `json:"ops,omitempty"`
	N       int64    `json:"n,omitempty"`
}

func control(ctx context.Context, h *harness, out *json.Encoder, in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		var c command
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			if err := out.Encode(map[string]string{"error": err.Error()}); err != nil {
				return err
			}
			continue
		}
		result, err := h.apply(c)
		if err != nil {
			if err := out.Encode(map[string]string{"error": err.Error()}); err != nil {
				return err
			}
			continue
		}
		if err := out.Encode(map[string]any{"ok": result}); err != nil {
			return err
		}
	}
	return sc.Err()
}

var modes = map[string]cipherontest.Mode{
	"Honest": cipherontest.Honest, "JunkCiphertext": cipherontest.JunkCiphertext,
	"GarbledPlaintext": cipherontest.GarbledPlaintext, "ForeignResponseSignature": cipherontest.ForeignResponseSignature,
	"NoResponseSignature": cipherontest.NoResponseSignature, "ShortSignature": cipherontest.ShortSignature,
	"ForeignSignature": cipherontest.ForeignSignature, "UnknownKeyID": cipherontest.UnknownKeyID,
	"WrongFormatCiphertext": cipherontest.WrongFormatCiphertext, "ForgedKeysSignature": cipherontest.ForgedKeysSignature,
	"KeysForOtherProfile": cipherontest.KeysForOtherProfile, "KeysForOtherContext": cipherontest.KeysForOtherContext,
	"KeysOfAnotherIdentity": cipherontest.KeysOfAnotherIdentity, "UnsignedExtraKey": cipherontest.UnsignedExtraKey,
	"UnknownTenancy": cipherontest.UnknownTenancy, "UnknownFormatCiphertext": cipherontest.UnknownFormatCiphertext,
	"UnknownVersionBlob": cipherontest.UnknownVersionBlob, "SignRevoked": cipherontest.SignRevoked,
	"ForgedKeyStatement": cipherontest.ForgedKeyStatement, "NoHPKESuite": cipherontest.NoHPKESuite,
	"AssociatedDataDropped": cipherontest.AssociatedDataDropped, "ReplayedKeys": cipherontest.ReplayedKeys,
	"UnknownSigningKeyState": cipherontest.UnknownSigningKeyState, "AnswerOtherContext": cipherontest.AnswerOtherContext,
	"LongCiphertext": cipherontest.LongCiphertext, "OtherKeyIDCiphertext": cipherontest.OtherKeyIDCiphertext,
	"NoSecondSignature": cipherontest.NoSecondSignature, "ShortBatch": cipherontest.ShortBatch,
}

var faults = map[string]cipherontest.Fault{
	"NoFault": cipherontest.NoFault, "Busy": cipherontest.Busy, "NoWriter": cipherontest.NoWriter,
	"Internal": cipherontest.Internal, "Unimplemented": cipherontest.Unimplemented,
	"Overloaded": cipherontest.Overloaded, "ProfileSealed": cipherontest.ProfileSealed,
}

func (h *harness) apply(c command) (any, error) {
	fake := h.fake
	switch c.Op {
	case "refuseCertificates":
		h.refuse.Store(c.N != 0)
	case "setMode":
		m, ok := modes[c.Mode]
		if !ok {
			return nil, fmt.Errorf("no mode %q", c.Mode)
		}
		fake.SetMode(m)
	case "fail", "failPublicKey":
		f, ok := faults[c.Fault]
		if !ok {
			return nil, fmt.Errorf("no fault %q", c.Fault)
		}
		if c.Op == "fail" {
			fake.Fail(f)
		} else {
			fake.FailPublicKey(f)
		}
	case "rotateSigning":
		return hex.EncodeToString(fake.RotateSigning(c.Profile)), nil
	case "addSigningKey":
		return hex.EncodeToString(fake.AddSigningKey(c.Profile)), nil
	case "activateSigning", "revokeSigning", "unrevokeSigning":
		id, err := hex.DecodeString(c.KeyID)
		if err != nil {
			return nil, err
		}
		switch c.Op {
		case "activateSigning":
			fake.ActivateSigning(c.Profile, id)
		case "revokeSigning":
			fake.RevokeSigning(c.Profile, id)
		default:
			fake.UnrevokeSigning(c.Profile, id)
		}
	case "activeKeyId":
		return hex.EncodeToString(fake.ActiveKeyID(c.Profile)), nil
	case "setWriteVersion":
		fake.SetWriteVersion(c.Profile, c.Version)
	case "retireVersion":
		fake.RetireVersion(c.Profile, c.Version)
	case "listVersion":
		fake.ListVersion(c.Profile, c.Version)
	case "rekey":
		fake.Rekey(c.Profile)
	case "requireRequestKey":
		pub, err := publicKeyOf(c.PEM)
		if err != nil {
			return nil, err
		}
		fake.RequireRequestKey(c.Profile, pub)
	case "grant":
		ops := make([]transport.Operation, len(c.Ops))
		for i, o := range c.Ops {
			ops[i] = transport.Operation(o)
		}
		fake.Grant(c.Profile, ops...)
	case "restart":
		fake.Restart(time.Now().Add(time.Duration(c.N) * time.Millisecond))
	case "setBatchMaxItems":
		fake.SetBatchMaxItems(int(c.N))
	case "setBatchMaxBytes":
		fake.SetBatchMaxBytes(c.N)
	case "newTenantKey":
		return hex.EncodeToString(fake.NewTenantKey(c.Profile, c.Tenant)), nil
	case "fingerprint":
		return fake.Fingerprint(c.Profile), nil
	case "contextDigest":
		return fake.ContextDigest(c.Profile), nil
	case "counters":
		verified, absent, refused := fake.Auth()
		return map[string]int64{"publicKeyCalls": fake.PublicKeyCalls(), "batchCalls": fake.BatchCalls(),
			"authVerified": verified, "authAbsent": absent, "authRefused": refused}, nil
	default:
		return nil, fmt.Errorf("no operation %q", c.Op)
	}
	return true, nil
}

// publicKeyOf reads a PEM PKIX Ed25519 public key, or derives it from a PEM PKCS #8 private key.
func publicKeyOf(s string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return transport.ParseRequestPublicKey([]byte(s))
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 key")
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("not an Ed25519 key")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("a PEM %q block is no request key", block.Type)
}
