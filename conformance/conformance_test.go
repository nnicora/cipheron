package conformance

// conformance_test.go — the kit holds what it says: the reference (wire/transport) passes every case; an
// implementation that is wrong in one kind fails exactly that kind's cases; a program run over JSON lines (Exec) is held
// to the same cases, and one that answers out of order or garbles its answers is a failure, never a pass; the schema
// names every kind the runner knows.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nnicora/cipheron/wire/transport"
)

func TestTheReferencePassesEveryCase(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(t.Context(), Reference(), s)
	if err != nil || !r.OK() || r.Passed != len(s.Cases) || r.Unsupported != 0 {
		t.Fatalf("the reference: %v\n%s", err, r)
	}
	for _, k := range Kinds() {
		if r.ByKind[k] == nil || r.ByKind[k].Passed == 0 {
			t.Errorf("no case of kind %s", k)
		}
	}
	// Every verification kind has a negative case: an implementation that answers valid to everything fails.
	for _, k := range []string{KindRequestSignature, KindResponseSignature, KindKeyStatement, KindReEncryptAssociatedData,
		KindTenantID} {
		n := 0
		for _, c := range s.Cases {
			if c.Kind == k && strings.Contains(string(c.Output), "false") {
				n++
			}
		}
		if n == 0 {
			t.Errorf("kind %s has no case whose answer is invalid", k)
		}
	}
}

// TestARefusalIsAnOutput (owner decision S34): a case of a refusable kind may have the output {"refused": true}, and
// only that spelling; every refusable kind has such cases; an implementation that never refuses — that reads a key id
// out of any bytes, or takes a blob for any tenant — fails exactly them; and one that answers an error where the case
// wants a refusal fails too (an error is never taken for a refusal).
func TestARefusalIsAnOutput(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	refusals := map[string]int{}
	for _, c := range s.Cases {
		if equalJSON(c.Output, json.RawMessage(refused)) {
			refusals[c.Kind]++
		}
	}
	for _, k := range RefusableKinds() {
		if refusals[k] == 0 {
			t.Errorf("kind %s has no refusal case", k)
		}
	}
	envelope := func(kind, output string) []byte {
		return []byte(`{"schema":"cipheron-conformance/v1","comment":"","transcriptVersion":1,"cases":[{"id":"a","kind":"` +
			kind + `","input":{},"output":` + output + `}]}`)
	}
	if _, err := Parse(envelope(KindTenantKey, `{"refused": true}`)); err != nil {
		t.Errorf("a refusal of a refusable kind: %v", err)
	}
	for _, c := range [][2]string{{KindDigest, `{"refused":true}`}, {KindTenantKey, `{"refused":false}`},
		{KindCiphertextKeyID, `{"refused":true,"keyId":"v1/0"}`}, {KindTenantKey, `{"refused":1}`}} {
		if _, err := Parse(envelope(c[0], c[1])); err == nil {
			t.Errorf("%s with output %s was accepted", c[0], c[1])
		}
	}

	r, err := Run(t.Context(), never{}, s)
	n := refusals[KindCiphertextKeyID] + refusals[KindTenantKey]
	if err != nil || r.OK() || r.Failed != n {
		t.Fatalf("an implementation that never refuses: %v, %d failed, want %d\n%s", err, r.Failed, n, r)
	}
	for _, f := range r.Failures {
		if !equalJSON(f.Want, json.RawMessage(refused)) {
			t.Errorf("a case that is not a refusal failed: %s", f.ID)
		}
	}
	r, err = Run(t.Context(), erring{}, s)
	if err != nil || r.OK() || r.Failed != n || r.Passed != len(s.Cases)-n {
		t.Fatalf("an implementation that answers an error for a refusal: %v\n%s", err, r)
	}
}

// never is the reference, but it never refuses: it reads a key id out of any bytes (cipheron's magic, a format byte,
// a length byte, the id) and takes any blob for the call's tenant and profile — the lax reader the kit must catch.
type never struct{}

func (never) Evaluate(ctx context.Context, kind string, in json.RawMessage) (json.RawMessage, error) {
	out, err := Reference().Evaluate(ctx, kind, in)
	if err != nil || !equalJSON(out, json.RawMessage(refused)) {
		return out, err
	}
	if kind == KindCiphertextKeyID {
		return json.RawMessage(`{"keyId":"v1/0"}`), nil
	}
	return json.RawMessage(`{"keyId":"00000000000000000000000000000000","signingPublicKey":"","wrappingVersion":"v1",` +
		`"created":1,"fingerprint":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`), nil
}

// erring is the reference, answering an error where it refuses.
type erring struct{}

func (erring) Evaluate(ctx context.Context, kind string, in json.RawMessage) (json.RawMessage, error) {
	out, err := Reference().Evaluate(ctx, kind, in)
	if err == nil && equalJSON(out, json.RawMessage(refused)) {
		return nil, errors.New("not a ciphertext")
	}
	return out, err
}

// TestALaxVerifierFailsTheSignatureEdges (DV-3, DV-5): a verifier that takes a signature of S not below L, or of the
// wrong length — it checks the point equation reduced mod L, or reads 64 bytes of whatever it is given — fails the
// kit's edge cases, and only them; the reference refuses them, and the keys signature replayed under another nonce.
func TestALaxVerifierFailsTheSignatureEdges(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	edges := 0
	for _, c := range s.Cases {
		if strings.HasSuffix(c.ID, "/s-plus-l") || strings.HasSuffix(c.ID, "/63-bytes") || strings.HasSuffix(c.ID, "/65-bytes") {
			edges++
		}
	}
	if edges != 6 {
		t.Fatalf("%d signature edge cases, want 6 (three of each signature kind)", edges)
	}
	// The 63-byte cases are refused by the lax verifier too (a byte of S is missing): the other four fail it.
	r, err := Run(t.Context(), lax{}, s)
	if err != nil || r.Failed != edges-2 {
		t.Fatalf("a lax verifier: %v, %d failed\n%s", err, r.Failed, r)
	}
	for _, f := range r.Failures {
		if !strings.HasSuffix(f.ID, "/s-plus-l") && !strings.HasSuffix(f.ID, "/65-bytes") {
			t.Errorf("a case that is not a signature edge failed: %s", f.ID)
		}
	}
	var replay bool
	for _, c := range s.Cases {
		replay = replay || strings.HasSuffix(c.ID, "/another-nonce") && c.Kind == KindResponseSignature && equalJSON(c.Output, json.RawMessage(`{"valid":false}`))
	}
	if !replay {
		t.Error("no keys signature checked under another nonce")
	}
}

// lax is the reference with a lax Ed25519 verifier: S is reduced mod L before the check, and a signature longer than
// 64 bytes is cut to 64, a shorter one padded.
type lax struct{}

func (lax) Evaluate(ctx context.Context, kind string, in json.RawMessage) (json.RawMessage, error) {
	if kind != KindRequestSignature && kind != KindResponseSignature {
		return Reference().Evaluate(ctx, kind, in)
	}
	var x SignatureInput
	if err := decodeStrict(in, &x); err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	copy(sig, x.Signature)
	sc := new(big.Int).SetBytes(reversed(sig[32:]))
	sc.Mod(sc, ed25519L)
	sc.FillBytes(sig[32:])
	copy(sig[32:], reversed(sig[32:]))
	return json.Marshal(ValidOutput{Valid: ed25519.Verify(ed25519.PublicKey(x.PublicKey), x.Transcript, sig)})
}

func reversed(b []byte) []byte {
	r := bytes.Clone(b)
	slices.Reverse(r)
	return r
}

// TestTheSchemaHoldsTheTenantRule (DV-4): the schema's tenant is the rule's — 1 to 2048 bytes of 0x21 to 0x7E — and
// every seal info's tenant is one, or empty for a shared profile: the pattern (with its bound read as maxLength, which
// Go's regexp cannot repeat 2048 times) agrees with transport.ValidTenant on the rule's edges.
func TestTheSchemaHoldsTheTenantRule(t *testing.T) {
	var sch struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(Schema(), &sch); err != nil {
		t.Fatal(err)
	}
	var tenant struct {
		MinLength int    `json:"minLength"`
		MaxLength int    `json:"maxLength"`
		Pattern   string `json:"pattern"`
	}
	if err := json.Unmarshal(sch.Defs["tenant"], &tenant); err != nil {
		t.Fatal(err)
	}
	if tenant.Pattern != "^[!-~]{1,2048}$" || tenant.MinLength != 1 || tenant.MaxLength != transport.MaxTenantLen {
		t.Fatalf("the schema's tenant: %+v", tenant)
	}
	re := regexp.MustCompile(strings.Replace(tenant.Pattern, "{1,2048}", "+", 1))
	schemaValid := func(s string) bool {
		return len(s) >= tenant.MinLength && len(s) <= tenant.MaxLength && re.MatchString(s)
	}
	long := strings.Repeat("t", transport.MaxTenantLen)
	for _, s := range []string{"t_alpha", `acme|eu/"d"\%41`, "!", "~", long, long + "t", "t alpha", "t ", "", "t\x7f", "t\x00", "té"} {
		if schemaValid(s) != transport.ValidTenant(s) {
			t.Errorf("%q (%d bytes): the schema says %v, the rule %v", s, len(s), schemaValid(s), transport.ValidTenant(s))
		}
	}
	if schemaValid(long+"t") || schemaValid("t alpha") {
		t.Error("the schema takes a 2049-byte tenant, or one holding a space")
	}
	for _, k := range []string{KindRequestSealInfo, KindResponseSealInfo} {
		if !strings.Contains(string(Schema()), `"tenant": { "$ref": "#/$defs/tenantOrShared" }`) {
			t.Errorf("%s's tenant is not the rule's", k)
		}
	}
}

// wrong is the reference, wrong in one kind (a verification always valid, or one bit of a computed value flipped),
// and not implementing another.
type wrong struct{ broken, missing string }

func (w wrong) Evaluate(ctx context.Context, kind string, in json.RawMessage) (json.RawMessage, error) {
	if kind == w.missing {
		return nil, ErrUnsupported
	}
	out, err := Reference().Evaluate(ctx, kind, in)
	if err != nil || kind != w.broken {
		return out, err
	}
	if strings.Contains(string(out), `"valid"`) {
		return json.RawMessage(`{"valid":true}`), nil
	}
	s := string(out)
	i := strings.LastIndexAny(s, "0123456789abcdef")
	c := "0"
	if s[i] == '0' {
		c = "1"
	}
	return json.RawMessage(s[:i] + c + s[i+1:]), nil
}

func TestAWrongImplementationFails(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range Kinds() {
		missing := KindDigest // a kind that is not mandatory: unsupported in full is counted, not failed
		if k == KindDigest {
			missing = KindRequestTranscript
		}
		r, err := Run(t.Context(), wrong{broken: k, missing: missing}, s)
		if err != nil {
			t.Fatal(err)
		}
		if r.OK() || r.ByKind[k].Failed == 0 || r.ByKind[missing].Unsupported == 0 || r.ByKind[missing].Failed != 0 {
			t.Errorf("wrong in %s, missing %s:\n%s", k, missing, r)
		}
		for _, f := range r.Failures {
			if f.Kind != k {
				t.Errorf("wrong in %s: a %s case failed: %s", k, f.Kind, f.ID)
			}
		}
	}
}

// partial is the reference, answering unsupported for the cases skip names (by the case's input).
type partial struct {
	skip func(kind string, in json.RawMessage) bool
}

func (p partial) Evaluate(ctx context.Context, kind string, in json.RawMessage) (json.RawMessage, error) {
	if p.skip(kind, in) {
		return nil, ErrUnsupported
	}
	return Reference().Evaluate(ctx, kind, in)
}

// TestUnsupportedCountsOnlyForAWholeKind (owner decision S20): a kind answered unsupported in full is counted, not
// failed — unless it is a mandatory verification kind, whose every case must pass; a kind answered unsupported for
// some cases and answered for others fails the unsupported ones (an implementation does not pick the cases it is held
// to: the tampered signatures left out, say). The report says why.
func TestUnsupportedCountsOnlyForAWholeKind(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, c := range s.Cases {
		count[c.Kind]++
	}
	inputs := map[string]bool{} // the inputs of the cases whose answer is invalid
	for _, c := range s.Cases {
		if strings.Contains(string(c.Output), "false") {
			inputs[string(c.Input)] = true
		}
	}
	if !slices.Equal(MandatoryKinds(), []string{KindResponseSignature, KindSigningKeysTranscript, KindFingerprint,
		KindKeyStatement}) {
		t.Fatalf("the mandatory kinds: %v", MandatoryKinds())
	}

	// A non-mandatory kind left out in full: counted, the run passes.
	r, err := Run(t.Context(), partial{skip: func(k string, _ json.RawMessage) bool { return k == KindDigest }}, s)
	if err != nil || !r.OK() || r.Unsupported != count[KindDigest] || r.ByKind[KindDigest].Failed != 0 {
		t.Fatalf("digest unsupported in full: %v\n%s", err, r)
	}
	// Each mandatory kind left out in full: every case of it fails, the run does not pass.
	for _, m := range MandatoryKinds() {
		r, err := Run(t.Context(), partial{skip: func(k string, _ json.RawMessage) bool { return k == m }}, s)
		if err != nil || r.OK() || r.ByKind[m].Failed != count[m] || r.ByKind[m].Unsupported != 0 || r.Unsupported != 0 ||
			r.Failed != count[m] || !strings.Contains(r.String(), "is a mandatory kind") {
			t.Errorf("%s unsupported in full: %v\n%s", m, err, r)
		}
	}
	// Only the tampered cases of a verification kind left out: they fail.
	r, err = Run(t.Context(), partial{skip: func(k string, in json.RawMessage) bool {
		return k == KindResponseSignature && inputs[string(in)]
	}}, s)
	if err != nil || r.OK() || r.ByKind[KindResponseSignature].Failed == 0 || r.ByKind[KindResponseSignature].Passed == 0 ||
		r.Unsupported != 0 {
		t.Errorf("only the tampered responseSignature cases unsupported: %v\n%s", err, r)
	}
	// A non-mandatory kind left out in part: the cases left out fail, and the report says why.
	first := true
	r, err = Run(t.Context(), partial{skip: func(k string, _ json.RawMessage) bool {
		if k != KindDigest {
			return false
		}
		first = !first
		return first
	}}, s)
	half := count[KindDigest] / 2
	if err != nil || r.OK() || r.ByKind[KindDigest].Failed != half || r.ByKind[KindDigest].Passed != count[KindDigest]-half ||
		r.Unsupported != 0 || !strings.Contains(r.String(), "unsupported counts only for a whole kind") {
		t.Errorf("digest unsupported in part: %v\n%s", err, r)
	}
}

// The adapter: this test binary, run again with CIPHERON_CONFORMANCE_ADAPTER set, answers JSON lines with the
// reference — what a non-Go implementation's adapter does with its own code.
func TestMain(m *testing.M) {
	switch os.Getenv("CIPHERON_CONFORMANCE_ADAPTER") {
	case "reference":
		os.Exit(serveAdapter(os.Stdin, os.Stdout, false))
	case "out-of-order":
		os.Exit(serveAdapter(os.Stdin, os.Stdout, true))
	case "garbage":
		// Reads one case, answers a line that is no answer, and exits.
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		_, _ = io.WriteString(os.Stdout, "not json\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func serveAdapter(in io.Reader, out io.Writer, wrongID bool) int {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var q request
		if err := json.Unmarshal(sc.Bytes(), &q); err != nil {
			return 2
		}
		a := answer{ID: q.ID}
		if wrongID {
			a.ID = "x" + q.ID
		}
		o, err := Reference().Evaluate(context.Background(), q.Kind, q.Input)
		switch {
		case errors.Is(err, ErrUnsupported):
			a.Unsupported = true
		case err != nil:
			a.Error = err.Error()
		default:
			a.Output = o
		}
		if err := enc.Encode(a); err != nil {
			return 2
		}
	}
	return 0
}

func adapter(t *testing.T, mode string) *Process {
	t.Helper()
	t.Setenv("CIPHERON_CONFORMANCE_ADAPTER", mode)
	p, err := Exec(t.Context(), os.Stderr, os.Args[0], "-test.run=^$")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnAdapterProgramIsHeldToTheVectors(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p := adapter(t, "reference")
	r, err := Run(t.Context(), p, s)
	if cerr := p.Close(); cerr != nil {
		t.Errorf("the adapter's exit: %v", cerr)
	}
	if err != nil || !r.OK() || r.Passed != len(s.Cases) {
		t.Fatalf("the reference as an adapter program: %v\n%s", err, r)
	}

	// Answers out of order: the run stops with an error (an answer is never matched to another case).
	p = adapter(t, "out-of-order")
	if _, err := Run(t.Context(), p, s); err == nil || !strings.Contains(err.Error(), "in order") {
		t.Errorf("an adapter answering out of order: %v", err)
	}
	_ = p.Close()
	// An answer that is no answer, then nothing: failures and then an error, never a pass.
	p = adapter(t, "garbage")
	if r, err := Run(t.Context(), p, s); err == nil || r.Passed != 0 {
		t.Errorf("an adapter that answers nothing: %v, %+v", err, r)
	}
	_ = p.Close()
	if _, err := Exec(t.Context(), nil); err == nil {
		t.Error("Exec with no program")
	}
}

// TestTheSchemaNamesEveryKind: vectors.schema.json is JSON, lists exactly the runner's kinds, and gives each its own
// input and output shape; the vectors use only the fields the schema allows (Parse is strict on the envelope, the
// reference's decoder on each input).
func TestTheSchemaNamesEveryKind(t *testing.T) {
	var sch struct {
		Defs struct {
			Case struct {
				AllOf []struct {
					If struct {
						Properties struct {
							Kind struct {
								Const string   `json:"const"`
								Enum  []string `json:"enum"`
							} `json:"kind"`
						} `json:"properties"`
					} `json:"if"`
					Properties struct {
						Kind struct {
							Enum []string `json:"enum"`
						} `json:"kind"`
					} `json:"properties"`
				} `json:"allOf"`
			} `json:"case"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(Schema(), &sch); err != nil {
		t.Fatal(err)
	}
	var shaped, listed []string
	for _, a := range sch.Defs.Case.AllOf {
		if a.If.Properties.Kind.Const != "" {
			shaped = append(shaped, a.If.Properties.Kind.Const)
		}
		shaped = append(shaped, a.If.Properties.Kind.Enum...)
		listed = append(listed, a.Properties.Kind.Enum...)
	}
	want := Kinds()
	slices.Sort(want)
	slices.Sort(shaped)
	slices.Sort(listed)
	if !slices.Equal(shaped, want) || !slices.Equal(listed, want) {
		t.Fatalf("the schema shapes %v and lists %v; the runner knows %v", shaped, listed, want)
	}
	if _, err := Parse([]byte(`{"schema":"cipheron-conformance/v1","comment":"","transcriptVersion":1,"cases":[],"extra":1}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := Parse([]byte(`{"schema":"cipheron-conformance/v1","comment":"","transcriptVersion":1,"cases":[{"id":"a","kind":"nope","input":{},"output":{}}]}`)); err == nil {
		t.Error("an unknown kind was accepted")
	}
	// One transcript version: a file of another (or of none) is refused.
	for _, v := range []string{`"transcriptVersion":2,`, `"transcriptVersion":0,`, ``} {
		if _, err := Parse([]byte(`{"schema":"cipheron-conformance/v1","comment":"",` + v + `"cases":[]}`)); err == nil {
			t.Errorf("a file with %q was accepted", v)
		}
	}
	// An input carrying a field its kind does not have is refused by the reference (strict, as cipheron is).
	if _, err := Reference().Evaluate(t.Context(), KindDigest, json.RawMessage(`{"fields":[],"extra":"00"}`)); err == nil {
		t.Error("the reference accepted an unknown input field")
	}
	if _, err := Reference().Evaluate(t.Context(), KindDigest, json.RawMessage(`{"fields":["AB"]}`)); err == nil {
		t.Error("the reference accepted upper-case hex")
	}
}
