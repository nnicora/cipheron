package transport

// statement.go — a profile's key statement: its identity, tenancy, key-context digest and signing keys (states and
// algorithms), with the time cipheron issued it, signed by the profile's response key WITHOUT a request nonce. It is
// what a service publishes for verifiers that never talk to cipheron: anyone holding the profile's pinned
// fingerprint checks it offline — the identity inside must have that fingerprint, and the signature must verify
// under the response key inside it.
//
// It proves no freshness. A recorded statement verifies forever, so a verifier bounds its age by IssuedAt (a
// statement older than the verifier's maximum age is refused), and a verifier that once saw a key revoked keeps it
// revoked. The fresh, nonce-bound PublicKey answer (SigningKeysTranscript) is what a client relies on.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nnicora/cipheron/wire/format"
)

// keyStatementLabel opens a key statement. No other transcript or digest starts with it, so its signature is never
// another's.
var keyStatementLabel = format.LabelKeyStatement.String()

// KeyStatementVersion is the statement layout's version (the second field): the key statement kind's one version,
// written and read.
const KeyStatementVersion uint32 = 1

// refuseKeyStatement is the refusal of bytes that are not a key statement of a version read: it names the version
// written.
func refuseKeyStatement(_, writes uint32) error {
	return fmt.Errorf("%w: not a key statement of version %d", ErrKeyStatement, writes)
}

// MaxKeyStatementLen bounds a statement this package parses: the most signing keys and identity keys of the
// largest size fit in it.
const MaxKeyStatementLen = 1 << 20

// ErrKeyStatement is the refusal of bytes that are not a key statement of this layout, or of a statement that does
// not verify (its identity is not the pinned one, or its signature is not by its response key).
var ErrKeyStatement = errors.New("cipheron: not a valid key statement")

// KeyStatement is a profile's key statement (statement.go).
type KeyStatement struct {
	Profile string
	// IssuedAtMS is when cipheron issued the statement, milliseconds since the Unix epoch (cipheron's clock).
	IssuedAtMS    int64
	ContextDigest string
	Identity      Identity
	// SigningKeys are the profile's signing keys with their states and algorithms (none in a wrapped profile).
	SigningKeys []SigningKey
}

// IssuedAt is IssuedAtMS as a time.
func (s *KeyStatement) IssuedAt() time.Time { return time.UnixMilli(s.IssuedAtMS) }

// MarshalKeyStatement is s's bytes, in the layout p writes — what the response key signs. A function, not a method of
// KeyStatement: the client library re-exports KeyStatement, and its method set is what an application sees; the
// policy is the protocol's machinery.
//
//	lp("cipheron/v1|key_statement") lp(version: 4) lp(profile) lp(tenancy) lp(issued at: 8, ms) lp(context digest)
//	lp(hpke suite: 6) lp(hpke key) lp(response algorithm: 4) lp(response key)
//	lp(n: 4) n × (lp(role: 4) lp(algorithm id: 6 for an HPKE key, 4 otherwise) lp(public key))   canonical order
//	lp(k: 4) k × (lp(key id) lp(state number: 4) lp(algorithm: 4) lp(public key))                 ascending key id
//
// (lp: a 4-byte big-endian length and the bytes). The suite and the response algorithm are written as they are (the
// classical ones for every identity this release makes), never left implicit. It validates nothing.
func MarshalKeyStatement(p *format.Policy, s *KeyStatement) ([]byte, error) {
	w := format.Write(p, keyStatements, 0)
	return marshalStatement(w.Codec(), w.Version(), s)
}

// statementHead is a key statement's head, the kind's: lp(label) lp(version: 4). ParseKeyStatement reads it before a
// codec is chosen.
func statementHead(v uint32) transcript {
	return transcript(nil).addString(keyStatementLabel).addUint32(v)
}

// marshalStatement is s at version v of codec c: the head, then c's fields. Marshal writes it and ParseKeyStatement
// compares a statement it read against it (canonical form), so the head is written in one place.
func marshalStatement(c statementCodec, v uint32, s *KeyStatement) ([]byte, error) {
	return c.marshal(statementHead(v), s)
}

// appendStatementV1 appends version 1's fields — everything after the head — to t.
func appendStatementV1(t transcript, s *KeyStatement) (transcript, error) {
	id := s.Identity
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(s.IssuedAtMS))
	t = t.addString(s.Profile).
		addString(string(id.Tenancy)).add(ts[:]).addString(s.ContextDigest).add(id.Suite().bytes()).add(id.HPKE).
		addUint32(uint32(id.ResponseAlg())).add(id.Response).addUint32(uint32(len(id.Additional)))
	for _, e := range sortedAdditional(id.Additional) {
		t = append(t, e...)
	}
	keys := slices.Clone(s.SigningKeys)
	SortSigningKeys(keys)
	t = t.addUint32(uint32(len(keys)))
	for _, k := range keys {
		code, err := k.stateCode()
		if err != nil {
			return nil, err
		}
		t = t.add(k.KeyID).addUint32(code).addUint32(uint32(k.Alg())).add(k.PublicKey)
	}
	return t, nil
}

// reader reads a transcript's length-prefixed fields.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) field() []byte {
	if r.err || len(r.b) < 4 {
		r.err = true
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		r.err = true
		return nil
	}
	f := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return f
}

func (r *reader) uint32() uint32 {
	f := r.field()
	if len(f) != 4 {
		r.err = true
		return 0
	}
	return binary.BigEndian.Uint32(f)
}

func (r *reader) suite() HPKESuite {
	f := r.field()
	if len(f) != 6 {
		r.err = true
		return HPKESuite{}
	}
	return HPKESuite{KEM: binary.BigEndian.Uint16(f), KDF: binary.BigEndian.Uint16(f[2:]), AEAD: binary.BigEndian.Uint16(f[4:])}
}

// ParseKeyStatement reads a key statement: every field of the layout (Marshal), nothing after it, in canonical
// form (the bytes are exactly what Marshal writes of what was read), with a valid profile name, context digest,
// identity (as received: Identity.ValidateReceived) and signing-key list (ValidateReceivedSigningKeys: every state one
// of the three; an algorithm this package does not implement is kept, the key unusable). It does not verify the
// signature nor the fingerprint: VerifyKeyStatement does. Anything else is ErrKeyStatement.
func ParseKeyStatement(p *format.Policy, b []byte) (*KeyStatement, error) {
	if len(b) > MaxKeyStatementLen {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrKeyStatement, MaxKeyStatementLen)
	}
	r := &reader{b: b}
	if string(r.field()) != keyStatementLabel {
		return nil, refuseKeyStatement(0, format.Write(p, keyStatements, 0).Version())
	}
	v := r.uint32()
	scheme, err := format.Read(p, keyStatements, v)
	if err != nil {
		return nil, err
	}
	c := scheme.Codec()
	s := c.parse(r)
	if r.err || len(r.b) != 0 {
		return nil, fmt.Errorf("%w: malformed", ErrKeyStatement)
	}
	if s.Identity.HPKESuite == (HPKESuite{}) || s.Identity.ResponseAlgorithm == AlgorithmUnspecified {
		return nil, fmt.Errorf("%w: the suite and the response algorithm are written, never 0", ErrKeyStatement)
	}
	if !ValidProfile(s.Profile) {
		return nil, fmt.Errorf("%w: %q is not a profile name", ErrKeyStatement, s.Profile)
	}
	if !ValidFingerprint(s.ContextDigest) {
		return nil, fmt.Errorf("%w: %q is not a key-context digest", ErrKeyStatement, s.ContextDigest)
	}
	if err := s.Identity.ValidateReceived(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyStatement, err)
	}
	if err := ValidateReceivedSigningKeys(s.Identity, s.SigningKeys); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyStatement, err)
	}
	again, err := marshalStatement(c, v, s)
	if err != nil || !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: not in canonical form", ErrKeyStatement)
	}
	return s, nil
}

// parseStatementV1 reads version 1's fields after the head (appendStatementV1).
func parseStatementV1(r *reader) *KeyStatement {
	s := &KeyStatement{Profile: string(r.field())}
	s.Identity.Tenancy = Tenancy(r.field())
	if ts := r.field(); len(ts) == 8 {
		s.IssuedAtMS = int64(binary.BigEndian.Uint64(ts))
	} else {
		r.err = true
	}
	s.ContextDigest = string(r.field())
	s.Identity.HPKESuite = r.suite()
	s.Identity.HPKE = bytes.Clone(r.field())
	s.Identity.ResponseAlgorithm = SignatureAlgorithm(r.uint32())
	s.Identity.Response = bytes.Clone(r.field())
	n := r.uint32()
	if n > MaxAdditionalKeys {
		r.err = true
	}
	for i := uint32(0); i < n && !r.err; i++ {
		e := IdentityKey{Role: IdentityKeyRole(r.uint32())}
		if e.Role == RoleHPKE {
			e.Suite = r.suite()
		} else {
			e.Algorithm = SignatureAlgorithm(r.uint32())
		}
		e.PublicKey = bytes.Clone(r.field())
		s.Identity.Additional = append(s.Identity.Additional, e)
	}
	k := r.uint32()
	if k > MaxSigningKeys {
		r.err = true
	}
	for i := uint32(0); i < k && !r.err; i++ {
		key := SigningKey{KeyID: bytes.Clone(r.field())}
		key.State = SigningKeyStateOf(r.uint32())
		key.Algorithm = SignatureAlgorithm(r.uint32())
		key.PublicKey = bytes.Clone(r.field())
		if key.Algorithm == AlgorithmUnspecified {
			r.err = true // written explicitly, never 0
		}
		s.SigningKeys = append(s.SigningKeys, key)
	}
	return s
}

// VerifyKeyStatement parses statement (ParseKeyStatement) and checks it for profile against the pinned fingerprint
// fp: the statement names profile, its identity's fingerprint (Fingerprint) is fp, its response key is Ed25519 and
// signature is that key's signature over statement. Anything else is ErrKeyStatement (an identity that is not the
// pinned one is the refusal of a statement that is not the profile's). Its age is the caller's to judge (IssuedAt).
func VerifyKeyStatement(p *format.Policy, statement, signature []byte, profile, fp string) (*KeyStatement, error) {
	s, err := ParseKeyStatement(p, statement)
	if err != nil {
		return nil, err
	}
	switch {
	case s.Profile != profile:
		return nil, fmt.Errorf("%w: it is profile %q's, not %q's", ErrKeyStatement, s.Profile, profile)
	case !ValidFingerprint(fp) || !MatchesFingerprint(profile, s.Identity, fp):
		return nil, fmt.Errorf("%w: its identity is %s, not the pinned %s", ErrKeyStatement,
			Fingerprint(profile, s.Identity), fp)
	case !s.Identity.ResponseAlg().Implemented():
		return nil, fmt.Errorf("%w: its response key's algorithm %d is not implemented here", ErrKeyStatement,
			uint32(s.Identity.ResponseAlg()))
	case len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.Identity.Response, statement, signature):
		return nil, fmt.Errorf("%w: the signature is not the profile's response key's", ErrKeyStatement)
	}
	return s, nil
}

// KeyStatementExportFormat is the token an exported key statement names its layout by, the one this release writes.
const KeyStatementExportFormat = "cipheron-key-statement/1"

// keyStatementExportVersion is the export layout's version: the key statement export kind's one version.
const keyStatementExportVersion uint32 = 1

// ErrKeyStatementExport is the refusal of a document that is not an exported key statement of a layout p reads.
var ErrKeyStatementExport = errors.New("cipheron: not an exported key statement")

// ExportKeyStatement is the JSON document a verifier reads offline, in the layout p writes: {"format", "profile",
// "fingerprint", "statement": base64, "signature": base64}. The profile and the fingerprint are there for the reader's
// eyes; a verifier checks the statement against ITS OWN pin, never against the one written there.
func ExportKeyStatement(p *format.Policy, profile, fingerprint string, raw, signature []byte) ([]byte, error) {
	w := format.Write(p, statementExports, 0)
	doc, err := w.Codec().marshal(w.Marker(), profile, fingerprint, raw, signature)
	if err != nil {
		return nil, err
	}
	// The layout fills the kind's "format" member; a document whose member is not its token is one no reader would
	// find the layout of: refused here, as a programming error, instead of written.
	if named, ok := exportFormat(doc); !ok || named != w.Marker() {
		return nil, fmt.Errorf("cipheron: layout %s of the exported key statement does not name itself in \"format\"", w.Name())
	}
	return doc, nil
}

// exportFormat is the "format" member of an exported key statement, read alone (formatMember); false when the
// document is not a JSON object.
func exportFormat(doc []byte) (string, bool) {
	var named formatMember
	if err := json.NewDecoder(bytes.NewReader(doc)).Decode(&named); err != nil {
		return "", false
	}
	return named.Format, true
}

// ReadKeyStatementExport is the statement and signature an exported key statement holds. A document whose "format"
// is no token p reads, or that the token's layout refuses, is ErrKeyStatementExport; a statement or signature that is
// not base64 is the join of the two fields' base64 errors (errors.Join).
//
// THE "format" MEMBER IS THE KIND'S (formatMember): it is read alone, before any layout is chosen; every layout's
// document embeds it, and the rest of the document is the layout's own.
func ReadKeyStatementExport(p *format.Policy, exported []byte) (raw, signature []byte, err error) {
	named, ok := exportFormat(exported)
	if !ok {
		return nil, nil, ErrKeyStatementExport
	}
	s, err := format.Marked(p, statementExports, []byte(named))
	if err != nil {
		return nil, nil, err
	}
	raw, signature, ok, err = s.Codec().unmarshal(s.Marker(), exported)
	switch {
	case !ok:
		return nil, nil, ErrKeyStatementExport
	case err != nil:
		return nil, nil, err
	}
	return raw, signature, nil
}
