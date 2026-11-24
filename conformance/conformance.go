// Package conformance is cipheron's conformance kit: the protocol's vectors, packaged, and a runner that holds a client
// (or server) implementation in any language to them.
//
// THE VECTORS (spec/vectors/cipheron-conformance-v1.json, embedded through package spec; its JSON Schema spec/vectors/vectors.schema.json) are
// self-contained: every case names its kind, its input and the output a conforming implementation computes, every
// byte string in lower-case hex. The file names the protocol's transcript version once (transcriptVersion: 1, the
// one version, which every transcript and seal info of it binds). They are derived from the repository's frozen set
// (spec/frozen), and a test holds the kit to it byte for byte: the kit is never
// regenerated from code to make a reader pass. The keys in them are published test keys.
//
// The kinds (what an implementation must compute; spec/api.md, "Conformance kit", gives every layout):
//
//	digest                 Digest(fields): the payload digest of a request or an answer
//	requestTranscript      what a request key signs
//	requestSignature       an Ed25519 request signature over a transcript: valid or not
//	requestSealInfo        the HPKE info a request payload (Encrypt's plaintext, Sign's data) is sealed under
//	responseSealInfo       the HPKE info a Decrypt answer's plaintext is sealed under
//	responseTranscript     what the profile's response key signs over an answer (with the answering cipheron's
//	                       key-context digest)
//	responseSignature      an answer's response signature: valid or not (tampered cases included)
//	signingKeysTranscript  what the response key signs over a PublicKey answer
//	fingerprint            a profile identity's fingerprint (what a client pins)
//	keyStatement           a publishable signed key-list statement, verified against a pinned fingerprint
//	ciphertextKeyID        the key a ciphertext names in its header (what `cipheron client key-id` prints)
//	signingKeyID           a signing key's id from its algorithm and public key (an algorithm other than Ed25519's too)
//	segmentAssociatedData  the associated data a segment of a CPS1 segmented object is encrypted with
//	jsonFieldAssociatedData the associated data an encrypted JSON field is encrypted with
//	reEncryptAssociatedData a re-encryption's associated data: valid (true) only when the new ciphertext's is the
//	                       stored one's, byte for byte — a client sends no other: one that drops it cipheron answers
//	                       INVALID_ARGUMENT, one that changes it PERMISSION_DENIED unless the caller entry is granted
//	                       decrypt and encrypt
//	tenantKey              a tenant key blob's header, checked against the call's profile and tenant (the key id,
//	                       signing key, wrapping version, creation time and fingerprint), or its refusal
//	tenantFingerprint      a tenant key's fingerprint (what a client pins a tenant key by)
//	tenantSignedMessage    what a derived profile's signing key signs for a tenant
//	tenantId               whether a string is a tenant id (1 to 2048 bytes of 0x21 to 0x7E)
//	errorClass             a refusal's class and retry rule, from its status code, cipheron's ErrorInfo and its
//	                       RetryInfo (transport.Refusal)
//
// The rules' cases (reEncryptAssociatedData, tenantId, errorClass) are written from the rules themselves
// (transport.CheckReEncryptAssociatedData, transport.ValidTenant, transport.Refusal): they hold no bytes of the frozen
// set. The layouts' refusals (ciphertextKeyID, tenantKey) are derived from the frozen bytes and the layouts' registry
// (transport.Ciphertexts, transport.TenantKeys): every registered format gets its truncated and malformed headers, and
// the bytes no layout has are taken from the registry, so the kit follows the layouts the code reads.
//
// A REFUSAL IS AN OUTPUT. A case of a refusable kind (RefusableKinds) whose input an implementation must refuse — bytes
// that are not one of the layouts, a blob of another tenant or profile, one byte over a bound — has the output
// {"refused": true}, and an implementation answers exactly that. An error answer is never taken for a refusal: it
// fails, as every error does (an implementation that fails on everything does not pass the refusals).
//
// THE RUNNER. Run evaluates every case on an Implementation and reports per kind; Reference is wire/transport
// itself (it passes every case); Exec runs any program as an implementation over JSON lines on its standard input and
// output, one case per line:
//
//	in:  {"id": "<case id>", "kind": "<kind>", "input": {...}}
//	out: {"id": "<case id>", "output": {...}}  |  {"id": "...", "error": "<text>"}  |  {"id": "...", "unsupported": true}
//
// The program answers each line before it reads the next, and exits when its standard input closes.
//
// "UNSUPPORTED" COUNTS ONLY FOR A WHOLE KIND, AND NEVER FOR A VERIFICATION KIND (owner decision S20). A kind every case
// of which is answered unsupported is counted, not failed — an implementation that only verifies answers need not
// compute request transcripts. A kind some of whose cases are answered unsupported while others are answered (passed
// or failed) fails those cases: an implementation does not pick which cases of a kind it is held to (only the tampered
// signatures left out, say). And the verification kinds (MandatoryKinds: responseSignature, signingKeysTranscript,
// fingerprint, keyStatement) are the protocol's guarantees against an impostor: a case of theirs answered unsupported
// fails, so a run passes only when every one of their cases passed.
//
// `cipheron conformance run --adapter <program> [args]` is that, as a command.
package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/nnicora/cipheron/spec"
	"github.com/nnicora/cipheron/wire/transport"
)

// VectorsFile and SchemaFile are the embedded files' names.
const (
	VectorsFile = "vectors/cipheron-conformance-v1.json"
	SchemaFile  = "vectors/vectors.schema.json"
)

// SchemaID is the value of a vectors file's "schema" field.
const SchemaID = "cipheron-conformance/v1"

// files are the vectors and their schema, from the protocol contract (package spec).
var files = spec.Vectors

// The kinds.
const (
	KindDigest                = "digest"
	KindRequestTranscript     = "requestTranscript"
	KindRequestSignature      = "requestSignature"
	KindRequestSealInfo       = "requestSealInfo"
	KindResponseSealInfo      = "responseSealInfo"
	KindResponseTranscript    = "responseTranscript"
	KindResponseSignature     = "responseSignature"
	KindSigningKeysTranscript = "signingKeysTranscript"
	KindFingerprint           = "fingerprint"
	KindKeyStatement          = "keyStatement"
	KindCiphertextKeyID       = "ciphertextKeyID"
	// The wave-1 layouts (deep review 2026-11-12, wave C).
	KindSigningKeyID            = "signingKeyID"
	KindSegmentAssociatedData   = "segmentAssociatedData"
	KindJSONFieldAssociatedData = "jsonFieldAssociatedData"
	// The re-encryption's associated-data rule (owner decisions R8, 2026-11-18, and S2, 2026-11-19).
	KindReEncryptAssociatedData = "reEncryptAssociatedData"
	// The tenant layouts, the tenant rule and the refusals' classes (owner decision S34, 2026-11-19).
	KindTenantKey           = "tenantKey"
	KindTenantFingerprint   = "tenantFingerprint"
	KindTenantSignedMessage = "tenantSignedMessage"
	KindTenantID            = "tenantId"
	KindErrorClass          = "errorClass"
)

// Kinds lists every kind, in the order the report prints them.
func Kinds() []string {
	return []string{KindDigest, KindRequestTranscript, KindRequestSignature, KindRequestSealInfo, KindResponseSealInfo,
		KindResponseTranscript, KindResponseSignature, KindSigningKeysTranscript, KindFingerprint, KindKeyStatement,
		KindCiphertextKeyID, KindSigningKeyID, KindSegmentAssociatedData, KindJSONFieldAssociatedData,
		KindReEncryptAssociatedData, KindTenantKey, KindTenantFingerprint, KindTenantSignedMessage, KindTenantID,
		KindErrorClass}
}

// RefusableKinds lists the kinds a case of which may have the output {"refused": true}: those that read stored bytes
// an implementation must refuse when they are not one of the protocol's layouts.
func RefusableKinds() []string { return []string{KindCiphertextKeyID, KindTenantKey} }

// refused is the one refusal output.
const refused = `{"refused":true}`

// MandatoryKinds lists the verification kinds a run passes only with every case passed: what a client checks of a
// party that claims to be the profile's cipheron (the package comment). A case of theirs answered unsupported fails.
func MandatoryKinds() []string {
	return []string{KindResponseSignature, KindSigningKeysTranscript, KindFingerprint, KindKeyStatement}
}

// Case is one vector.
type Case struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Note   string          `json:"note,omitempty"`
	Input  json.RawMessage `json:"input"`
	Output json.RawMessage `json:"output"`
}

// Suite is a vectors file. TranscriptVersion is the protocol's transcript version the cases are of: the version this
// package writes, transport.WrittenTranscriptVersion (a file of any other is refused).
type Suite struct {
	Schema            string `json:"schema"`
	Comment           string `json:"comment"`
	TranscriptVersion uint32 `json:"transcriptVersion"`
	Cases             []Case `json:"cases"`
}

// Vectors returns the embedded vectors file's bytes.
func Vectors() []byte {
	b, err := files.ReadFile(VectorsFile)
	if err != nil {
		panic(err) // embedded at build time
	}
	return b
}

// Schema returns the embedded JSON Schema's bytes.
func Schema() []byte {
	b, err := files.ReadFile(SchemaFile)
	if err != nil {
		panic(err)
	}
	return b
}

// Load parses the embedded vectors.
func Load() (*Suite, error) { return Parse(Vectors()) }

// Parse reads a vectors file strictly: unknown fields are refused, the transcript version is the one written
// (transport.WrittenTranscriptVersion), every case has an id, a known kind, an input and an output, no id repeats, and
// an output that names "refused" is exactly {"refused": true}, of a refusable kind (RefusableKinds).
func Parse(b []byte) (*Suite, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Suite
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("conformance: the vectors: %w", err)
	}
	if s.Schema != SchemaID {
		return nil, fmt.Errorf("conformance: the vectors are %q, not %q", s.Schema, SchemaID)
	}
	if w := transport.WrittenTranscriptVersion(transport.Release()); s.TranscriptVersion != w {
		return nil, fmt.Errorf("conformance: the vectors are of transcript version %d; this protocol's is %d",
			s.TranscriptVersion, w)
	}
	known, refusable := map[string]bool{}, map[string]bool{}
	for _, k := range Kinds() {
		known[k] = true
	}
	for _, k := range RefusableKinds() {
		refusable[k] = true
	}
	seen := map[string]bool{}
	for i, c := range s.Cases {
		switch {
		case c.ID == "" || seen[c.ID]:
			return nil, fmt.Errorf("conformance: case %d: id %q missing or repeated", i, c.ID)
		case !known[c.Kind]:
			return nil, fmt.Errorf("conformance: case %s: unknown kind %q", c.ID, c.Kind)
		case len(c.Input) == 0 || len(c.Output) == 0:
			return nil, fmt.Errorf("conformance: case %s: no input or output", c.ID)
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(c.Output, &out); err != nil {
			return nil, fmt.Errorf("conformance: case %s: the output is not an object: %w", c.ID, err)
		}
		if _, ok := out["refused"]; ok && (!refusable[c.Kind] || !equalJSON(c.Output, json.RawMessage(refused))) {
			return nil, fmt.Errorf("conformance: case %s: a refusal is {\"refused\": true}, of a kind of %v", c.ID,
				RefusableKinds())
		}
		seen[c.ID] = true
	}
	return &s, nil
}

// ErrUnsupported is what an Implementation answers for a kind it does not implement: counted, not failed, when it
// answers it for every case of a kind that is not one of MandatoryKinds (the package comment).
var ErrUnsupported = errors.New("conformance: kind not supported by this implementation")

// Implementation computes a case's output from its input.
type Implementation interface {
	Evaluate(ctx context.Context, kind string, input json.RawMessage) (json.RawMessage, error)
}

// Failure is a case an implementation did not pass.
type Failure struct {
	ID, Kind, Note string
	Want           json.RawMessage
	Got            json.RawMessage
	Err            string
}

// KindReport counts one kind's cases. Unsupported counts only a kind's cases all answered unsupported, of a kind that
// is not mandatory; any other case answered unsupported is Failed.
type KindReport struct{ Passed, Failed, Unsupported int }

// Report is what Run found.
type Report struct {
	Passed, Failed, Unsupported int
	ByKind                      map[string]*KindReport
	Failures                    []Failure
}

// OK reports whether nothing failed and something passed: every case of the mandatory kinds passed, and every other
// kind passed in full or was answered unsupported in full (Run fails any other unsupported case).
func (r *Report) OK() bool { return r.Failed == 0 && r.Passed > 0 }

// String is the report as `cipheron conformance run` prints it.
func (r *Report) String() string {
	var b strings.Builder
	for _, k := range Kinds() {
		if kr := r.ByKind[k]; kr != nil {
			fmt.Fprintf(&b, "%-22s passed %d, failed %d, unsupported %d\n", k, kr.Passed, kr.Failed, kr.Unsupported)
		}
	}
	for _, f := range r.Failures {
		if f.Err != "" {
			fmt.Fprintf(&b, "FAIL %s (%s): %s\n", f.ID, f.Kind, f.Err)
		} else {
			fmt.Fprintf(&b, "FAIL %s (%s): want %s, got %s\n", f.ID, f.Kind, f.Want, f.Got)
		}
	}
	fmt.Fprintf(&b, "total: passed %d, failed %d, unsupported %d\n", r.Passed, r.Failed, r.Unsupported)
	return b.String()
}

// Run evaluates every case of s on impl. A transport failure of impl (ctx cancelled, an Exec program gone) stops it
// with an error; a wrong answer is a Failure; so is a case answered unsupported unless the kind is not mandatory and
// every case of it was answered unsupported (the package comment).
func Run(ctx context.Context, impl Implementation, s *Suite) (*Report, error) {
	r := &Report{ByKind: map[string]*KindReport{}}
	unsupported := map[string][]Case{} // per kind, the cases answered unsupported
	defer func() { r.judgeUnsupported(unsupported) }()
	for _, c := range s.Cases {
		kr := r.ByKind[c.Kind]
		if kr == nil {
			kr = &KindReport{}
			r.ByKind[c.Kind] = kr
		}
		got, err := impl.Evaluate(ctx, c.Kind, c.Input)
		switch {
		case errors.Is(err, ErrUnsupported):
			kr.Unsupported++
			r.Unsupported++
			unsupported[c.Kind] = append(unsupported[c.Kind], c)
			continue
		case errors.Is(err, errTransport):
			return r, err
		case err != nil:
			kr.Failed++
			r.Failed++
			r.Failures = append(r.Failures, Failure{ID: c.ID, Kind: c.Kind, Note: c.Note, Want: c.Output, Err: err.Error()})
			continue
		}
		if equalJSON(c.Output, got) {
			kr.Passed++
			r.Passed++
			continue
		}
		kr.Failed++
		r.Failed++
		r.Failures = append(r.Failures, Failure{ID: c.ID, Kind: c.Kind, Note: c.Note, Want: c.Output, Got: got})
	}
	return r, nil
}

// judgeUnsupported turns the cases answered unsupported that do not count as such into failures: every case of a
// mandatory kind, and every case of a kind some of whose other cases were answered. It then orders the failures.
func (r *Report) judgeUnsupported(unsupported map[string][]Case) {
	mandatory := map[string]bool{}
	for _, k := range MandatoryKinds() {
		mandatory[k] = true
	}
	for _, kind := range Kinds() {
		cases, kr := unsupported[kind], r.ByKind[kind]
		if len(cases) == 0 || kr == nil {
			continue
		}
		var why string
		switch {
		case mandatory[kind]:
			why = fmt.Sprintf("answered unsupported, and %s is a mandatory kind (%s): a pass needs every one of their "+
				"cases passed", kind, strings.Join(MandatoryKinds(), ", "))
		case kr.Passed > 0 || kr.Failed > 0:
			why = fmt.Sprintf("answered unsupported while other cases of %s were answered: unsupported counts only for a "+
				"whole kind", kind)
		default:
			continue
		}
		kr.Unsupported -= len(cases)
		r.Unsupported -= len(cases)
		kr.Failed += len(cases)
		r.Failed += len(cases)
		for _, c := range cases {
			r.Failures = append(r.Failures, Failure{ID: c.ID, Kind: c.Kind, Note: c.Note, Want: c.Output, Err: why})
		}
	}
	sort.SliceStable(r.Failures, func(i, j int) bool { return r.Failures[i].ID < r.Failures[j].ID })
}

// equalJSON compares two JSON values as values (key order and spacing aside; numbers as written).
func equalJSON(a, b json.RawMessage) bool {
	var x, y any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	if da.Decode(&x) != nil || db.Decode(&y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// errTransport marks a failure to reach an implementation, which stops Run.
var errTransport = errors.New("conformance: the implementation could not be reached")

// maxAnswer bounds one answer line of an Exec program.
const maxAnswer = 1 << 20

// Process is a program run as an Implementation over JSON lines (Exec). Close it when done.
type Process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	out    *bufio.Reader
	mu     sync.Mutex
	nextID int
}

// Exec starts argv[0] with argv[1:] as an Implementation (see the package comment for the protocol). Its standard
// error is passed to stderr (nil: discarded).
func Exec(ctx context.Context, stderr io.Writer, argv ...string) (*Process, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("conformance: no adapter program named")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // the operator names the adapter it tests
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("conformance: starting the adapter %s: %w", argv[0], err)
	}
	return &Process{cmd: cmd, stdin: stdin, out: bufio.NewReaderSize(stdout, 64<<10)}, nil
}

type request struct {
	ID    string          `json:"id"`
	Kind  string          `json:"kind"`
	Input json.RawMessage `json:"input"`
}

type answer struct {
	ID          string          `json:"id"`
	Output      json.RawMessage `json:"output,omitempty"`
	Error       string          `json:"error,omitempty"`
	Unsupported bool            `json:"unsupported,omitempty"`
}

// Evaluate sends one case and reads its answer.
func (p *Process) Evaluate(ctx context.Context, kind string, input json.RawMessage) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", errTransport, err)
	}
	p.nextID++
	id := fmt.Sprintf("c%d", p.nextID)
	line, err := json.Marshal(request{ID: id, Kind: kind, Input: input})
	if err != nil {
		return nil, err
	}
	if _, err := p.stdin.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("%w: writing to the adapter: %w", errTransport, err)
	}
	raw, err := readLine(p.out)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the adapter's answer: %w", errTransport, err)
	}
	var a answer
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("the adapter's answer is not an answer line: %w", err)
	}
	switch {
	case a.ID != id:
		return nil, fmt.Errorf("%w: the adapter answered %q to %q (answers must come in order)", errTransport, a.ID, id)
	case a.Unsupported:
		return nil, ErrUnsupported
	case a.Error != "":
		return nil, errors.New(a.Error)
	case len(a.Output) == 0:
		return nil, errors.New("the adapter answered no output")
	}
	return a.Output, nil
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxAnswer {
			return nil, fmt.Errorf("an answer longer than %d bytes", maxAnswer)
		}
		if !isPrefix {
			return line, nil
		}
	}
}

// Close closes the program's standard input and waits for it to exit.
func (p *Process) Close() error {
	_ = p.stdin.Close()
	return p.cmd.Wait()
}
