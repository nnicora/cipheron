//go:build linux || darwin

package cipheron_test

// reencrypt_fake_test.go — the re-encryption of JSON fields and segmented objects (ReEncryptJSONFields,
// ReEncryptObject, ReEncryptStream, and their tenant forms) against the fake: what a key rotation's sweep moves, moved
// by a caller granted reencrypt alone — its decrypt is refused, so no plaintext reaches it — with the associated data
// kept or changed (never dropped: targetaad_fake_test.go); every refusal all-or-nothing, with DecryptJSONFields' and
// DecryptObject's failure modes; and JSONFieldKeyID, the field-key reader a sweep decides with. And the rollback
// pattern client-library.md describes: a version number in the associated data refuses an older ciphertext put back,
// and a re-encryption keeps it.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nnicora/cipheron"
	"github.com/nnicora/cipheron/cipherontest"
	"github.com/nnicora/cipheron/wire/transport"
)

// allOps grants profile of fake every operation the tests here use; reencryptOnly grants it reencrypt alone, as a
// migrator's entry.
func allOps(fake *cipherontest.Server, profile string) {
	fake.Grant(profile, transport.OpEncrypt, transport.OpDecrypt, transport.OpReEncrypt, transport.OpProvision)
}

func reencryptOnly(fake *cipherontest.Server, profile string) {
	fake.Grant(profile, transport.OpReEncrypt)
}

// fieldAt is the value at pointer (object keys and array indexes, no escapes) of the JSON document doc.
func fieldAt(t *testing.T, doc []byte, pointer string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}
	for _, tok := range strings.Split(pointer[1:], "/") {
		switch x := v.(type) {
		case map[string]any:
			v = x[tok]
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil {
				t.Fatal(err)
			}
			v = x[i]
		default:
			t.Fatalf("%s: no value", pointer)
		}
	}
	return v
}

// fieldKey is the key the encrypted field at pointer of doc names (JSONFieldKeyID).
func fieldKey(t *testing.T, doc []byte, pointer string) string {
	t.Helper()
	s, _ := fieldAt(t, doc, pointer).(string)
	k, err := cipheron.JSONFieldKeyID(s)
	if err != nil {
		t.Fatalf("%s: %v", pointer, err)
	}
	return k.String()
}

// segmentKeys are the keys of every segment of object, and its header.
func segmentKeys(t *testing.T, object []byte) (transport.SegmentedHeader, []string) {
	t.Helper()
	h, segs, err := transport.ParseSegmented(transport.Release(), object)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, len(segs))
	for i, s := range segs {
		k, err := cipheron.KeyID(s)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k.String()
	}
	return h, keys
}

// errText is err's message, "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func allAre(keys []string, want string) bool {
	for _, k := range keys {
		if k != want {
			return false
		}
	}
	return len(keys) > 0
}

func TestReEncryptJSONFields(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	doc := []byte(`{"card":{"cvv":123,"number":"4111111111111111"},"id":"r-1","tags":["a","b"]}`)
	ptrs := []string{"/card/number", "/card/cvv", "/tags/1"}
	coll := cipheron.WithAssociatedData([]byte("payments"))
	enc, err := c.EncryptJSONFields(ctx, "docs", doc, "r-1", ptrs, coll)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ptrs {
		if k := fieldKey(t, enc, p); k != "v1" {
			t.Fatalf("%s is under %s", p, k)
		}
	}

	// The rotation: v2 writes. The migrator's entry may reencrypt, nothing else: it cannot read a field.
	fake.SetWriteVersion("docs", "v2")
	reencryptOnly(fake, "docs")
	if _, err := c.DecryptJSONFields(ctx, "docs", enc, "r-1", ptrs, coll); !errors.Is(err, cipheron.ErrPermissionDenied) {
		t.Fatalf("the migrator's DecryptJSONFields: %v", err)
	}
	moved, err := c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs, coll, cipheron.WithTargetAssociatedData([]byte("payments")))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ptrs {
		if k := fieldKey(t, moved, p); k != "v2" {
			t.Fatalf("%s moved to %s, want v2", p, k)
		}
		if fieldAt(t, moved, p) == fieldAt(t, enc, p) {
			t.Fatalf("%s: the same ciphertext", p)
		}
	}
	if bytes.Contains(moved, []byte("4111111111111111")) || fieldAt(t, moved, "/id") != "r-1" || fieldAt(t, moved, "/tags/0") != "a" {
		t.Fatalf("the moved document: %s", moved)
	}
	// One field alone moves alone: the others keep their ciphertexts.
	one, err := c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs[:1], coll, cipheron.WithTargetAssociatedData([]byte("payments")))
	if err != nil || fieldKey(t, one, ptrs[0]) != "v2" || fieldAt(t, one, ptrs[1]) != fieldAt(t, enc, ptrs[1]) {
		t.Fatalf("one field: %s %v", one, err)
	}

	// Read back by the service's entry: the same document, with the associated data kept.
	allOps(fake, "docs")
	if dec, err := c.DecryptJSONFields(ctx, "docs", moved, "r-1", ptrs, coll); err != nil || string(dec) != string(doc) {
		t.Fatalf("the moved fields: %s %v", dec, err)
	}
	// Without WithTargetAssociatedData the call is refused before anything is sent, as ReEncrypt is (the caller's
	// associated data would be dropped; targetaad_fake_test.go), and so is other associated data: a re-encryption keeps
	// the binding.
	batches := fake.BatchCalls()
	if bare, err := c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs, coll); bare != nil ||
		!errors.Is(err, cipheron.ErrAssociatedData) || fake.BatchCalls() != batches {
		t.Fatalf("no target associated data: %q %v", bare, err)
	}
	if archived, err := c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs, coll,
		cipheron.WithTargetAssociatedData([]byte("archive"))); archived != nil || !errors.Is(err, cipheron.ErrAssociatedData) ||
		fake.BatchCalls() != batches {
		t.Fatalf("other target associated data: %q %v", archived, err)
	}

	// All or nothing: one field under a version cipheron no longer lists fails the call, nothing returned.
	half, err := c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs[1:], coll, cipheron.WithTargetAssociatedData([]byte("payments")))
	if err != nil {
		t.Fatal(err)
	}
	fake.RetireVersion("docs", "v1")
	out, err := c.ReEncryptJSONFields(ctx, "docs", half, "r-1", ptrs, coll, cipheron.WithTargetAssociatedData([]byte("payments")))
	if out != nil || !errors.Is(err, cipheron.ErrKeyVersionUnavailable) || !strings.Contains(err.Error(), ptrs[0]) {
		t.Fatalf("a field under a retired version: %q %v", out, err)
	}
	fake.ListVersion("docs", "v1")

	// DecryptJSONFields' refusals: another record or other associated data does not decrypt (ErrInvalidInput); what
	// the call cannot use is refused before anything is sent (ErrJSONField).
	for name, f := range map[string]func() ([]byte, error){
		"another record": func() ([]byte, error) {
			return c.ReEncryptJSONFields(ctx, "docs", enc, "r-2", ptrs, coll, cipheron.WithTargetAssociatedData([]byte("payments")))
		},
		"other associated data": func() ([]byte, error) {
			return c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs, cipheron.WithTargetAssociatedData([]byte("payments")))
		},
	} {
		if out, err := f(); out != nil || !errors.Is(err, cipheron.ErrInvalidInput) || errors.Is(err, cipheron.ErrJSONField) {
			t.Errorf("%s: %q %v; want ErrInvalidInput", name, out, err)
		}
	}
	calls := fake.BatchCalls()
	cvv, _ := fieldAt(t, enc, "/card/cvv").(string)
	inClear := strings.Replace(string(enc), strconv.Quote(cvv), "123", 1)
	keepColl := cipheron.WithTargetAssociatedData([]byte("payments"))
	for name, f := range map[string]func() ([]byte, error){
		"a field in clear": func() ([]byte, error) {
			return c.ReEncryptJSONFields(ctx, "docs", []byte(inClear), "r-1", ptrs, coll, keepColl)
		},
		"nested pointers": func() ([]byte, error) {
			return c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", []string{"/card", "/card/cvv"}, coll, keepColl)
		},
		"no record id": func() ([]byte, error) { return c.ReEncryptJSONFields(ctx, "docs", enc, "", ptrs, coll, keepColl) },
		"associated data over the bound with its framing": func() ([]byte, error) {
			big := make([]byte, transport.MaxAssociatedDataLen-8)
			return c.ReEncryptJSONFields(ctx, "docs", enc, "r-1", ptrs, cipheron.WithAssociatedData(big),
				cipheron.WithTargetAssociatedData(big))
		},
	} {
		if out, err := f(); out != nil || !errors.Is(err, cipheron.ErrJSONField) || !errors.Is(err, cipheron.ErrInvalidInput) {
			t.Errorf("%s: %q %v; want ErrJSONField", name, out, err)
		}
	}
	if fake.BatchCalls() != calls {
		t.Fatalf("%d batches sent for inputs refused before sending", fake.BatchCalls()-calls)
	}

	// JSONFieldKeyID: a value that is not an encrypted field is ErrJSONField; one that holds no ciphertext is not.
	if _, err := cipheron.JSONFieldKeyID("123"); !errors.Is(err, cipheron.ErrJSONField) || !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("a clear value: %v", err)
	}
	if _, err := cipheron.JSONFieldKeyID(cipheron.JSONFieldPrefix + "AAAA"); !errors.Is(err, cipheron.ErrInvalidInput) ||
		errors.Is(err, cipheron.ErrJSONField) {
		t.Fatalf("a field holding no ciphertext: %v", err)
	}
}

func TestReEncryptObject(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	pt := random(t, 5*transport.MinSegmentSize+7)
	aad := cipheron.WithAssociatedData([]byte("records/contract.pdf"))
	keep := cipheron.WithTargetAssociatedData([]byte("records/contract.pdf"))
	enc, err := c.EncryptObject(ctx, "docs", pt, cipheron.WithSegmentSize(transport.MinSegmentSize), aad)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := segmentKeys(t, enc)

	fake.SetWriteVersion("docs", "v2")
	reencryptOnly(fake, "docs")
	if _, err := c.DecryptObject(ctx, "docs", enc, aad); !errors.Is(err, cipheron.ErrPermissionDenied) {
		t.Fatalf("the migrator's DecryptObject: %v", err)
	}
	fake.SetBatchMaxItems(2) // several batches: the segments stay in order
	calls := fake.BatchCalls()
	moved, err := c.ReEncryptObject(ctx, "docs", enc, aad, keep)
	if err != nil {
		t.Fatal(err)
	}
	if fake.BatchCalls()-calls < 3 {
		t.Fatalf("%d batches for 6 segments, 2 per batch", fake.BatchCalls()-calls)
	}
	fake.SetBatchMaxItems(0)
	h, keys := segmentKeys(t, moved)
	// The object keeps its id (every segment keeps its binding: a migrator granted reencrypt alone re-encrypts it).
	if !allAre(keys, "v2") || !bytes.Equal(h.ObjectID, old.ObjectID) || h.SegmentSize != old.SegmentSize || h.Count != old.Count {
		t.Fatalf("the moved object: %+v %v (was %+v)", h, keys, old)
	}
	allOps(fake, "docs")
	if got, err := c.DecryptObject(ctx, "docs", moved, aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("the moved object: %d bytes, %v", len(got), err)
	}
	if got, err := c.DecryptObject(ctx, "docs", enc, aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("the stored object, untouched: %v", err)
	}
	// The segment size is kept, and WithSegmentSize, given, must be it.
	if again, err := c.ReEncryptObject(ctx, "docs", enc, aad, keep, cipheron.WithSegmentSize(transport.MinSegmentSize)); err != nil {
		t.Fatal(err)
	} else if got, err := c.DecryptObject(ctx, "docs", again, aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("the object's own segment size: %v", err)
	}

	// Refused whole, nothing returned: DecryptObject's failures, and what is refused before anything is sent.
	_, segs, _ := transport.ParseSegmented(transport.Release(), enc)
	other, _ := c.EncryptObject(ctx, "docs", pt, cipheron.WithSegmentSize(transport.MinSegmentSize), aad)
	_, osegs, _ := transport.ParseSegmented(transport.Release(), other)
	frame := func(hh transport.SegmentedHeader, ss ...[]byte) []byte {
		b, err := transport.AppendSegmentedHeader(transport.Release(), nil, hh)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range ss {
			b = transport.AppendSegment(b, s)
		}
		return b
	}
	cut := old
	cut.Count--
	wide := old
	wide.SegmentSize *= 2
	for name, tc := range map[string]struct {
		object []byte
		opts   []cipheron.CallOption
		want   error
		sent   bool
	}{
		"two segments swapped":        {frame(old, segs[0], segs[2], segs[1], segs[3], segs[4], segs[5]), []cipheron.CallOption{aad, keep}, cipheron.ErrSegmented, true},
		"the last segment dropped":    {frame(cut, segs[:5]...), []cipheron.CallOption{aad, keep}, cipheron.ErrSegmented, true},
		"a segment of another object": {frame(old, segs[0], segs[1], osegs[2], segs[3], segs[4], segs[5]), []cipheron.CallOption{aad, keep}, cipheron.ErrSegmented, true},
		"other associated data": {enc, []cipheron.CallOption{cipheron.WithAssociatedData([]byte("records/other.pdf")),
			cipheron.WithTargetAssociatedData([]byte("records/other.pdf"))}, cipheron.ErrSegmented, true},
		"a target's associated data alone": {enc, []cipheron.CallOption{keep}, cipheron.ErrAssociatedData, false},
		"other target associated data": {enc, []cipheron.CallOption{aad,
			cipheron.WithTargetAssociatedData([]byte("records/other.pdf"))}, cipheron.ErrAssociatedData, false},
		"bytes after the last segment": {append(append([]byte{}, enc...), 0), []cipheron.CallOption{aad, keep}, cipheron.ErrSegmented, false},
		"segments of another size":     {frame(wide, segs...), []cipheron.CallOption{aad, keep}, cipheron.ErrSegmented, false},
		"another segment size":         {enc, []cipheron.CallOption{aad, keep, cipheron.WithSegmentSize(2 * transport.MinSegmentSize)}, cipheron.ErrInvalidInput, false},
		"no target associated data":    {enc, []cipheron.CallOption{aad}, cipheron.ErrAssociatedData, false},
		"target associated data over an object's bound": {enc, []cipheron.CallOption{aad,
			cipheron.WithTargetAssociatedData(make([]byte, transport.MaxObjectAssociatedDataLen+1))}, cipheron.ErrAssociatedData, false},
	} {
		calls := fake.BatchCalls()
		out, err := c.ReEncryptObject(ctx, "docs", tc.object, tc.opts...)
		if out != nil || !errors.Is(err, tc.want) || !errors.Is(err, cipheron.ErrInvalidInput) {
			t.Errorf("%s: %d bytes, %v; want %v", name, len(out), err, tc.want)
		}
		if sent := fake.BatchCalls() != calls; sent != tc.sent {
			t.Errorf("%s: sent %v, want %v", name, sent, tc.sent)
		}
	}
	// An object's associated data is held to an object's bound, as EncryptObject holds its own: refused with that bound
	// before the object is read.
	overBound := make([]byte, transport.MaxObjectAssociatedDataLen+1)
	if _, err := c.ReEncryptObject(ctx, "docs", enc, cipheron.WithAssociatedData(overBound),
		cipheron.WithTargetAssociatedData(overBound)); !strings.Contains(errText(err), "an object's associated data is at most") {
		t.Fatalf("an object's associated data over its bound: %v", err)
	}
	// A segment under a version cipheron no longer lists: ErrKeyVersionUnavailable, not a tampered object.
	fake.RetireVersion("docs", "v1")
	if out, err := c.ReEncryptObject(ctx, "docs", enc, aad, keep); out != nil || !errors.Is(err, cipheron.ErrKeyVersionUnavailable) ||
		errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("an object under a retired version: %v", err)
	}
	fake.ListVersion("docs", "v1")

	// A large associated data is counted as cipheron counts a ReEncryptBatch item (with both of its sides): the batches
	// split by cipheron's limits, adopted from its refusal, and the object moves.
	large := bytes.Repeat([]byte("t"), 4<<10)
	bigEnc, err := c.EncryptObject(ctx, "docs", pt, cipheron.WithSegmentSize(transport.MinSegmentSize),
		cipheron.WithAssociatedData(large))
	if err != nil {
		t.Fatal(err)
	}
	fake.SetBatchMaxBytes(16 << 10)
	moved, err = c.ReEncryptObject(ctx, "docs", bigEnc, cipheron.WithAssociatedData(large), cipheron.WithTargetAssociatedData(large))
	fake.SetBatchMaxBytes(0)
	if err != nil {
		t.Fatalf("an associated data larger than a segment: %v", err)
	}
	if got, err := c.DecryptObject(ctx, "docs", moved, cipheron.WithAssociatedData(large)); err != nil ||
		!bytes.Equal(got, pt) {
		t.Fatalf("read back: %v", err)
	}
}

func TestReEncryptStream(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "docs")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("docs", fake.Fingerprint("docs")))
	pt := random(t, 40*transport.MinSegmentSize+3) // 41 segments
	aad := cipheron.WithAssociatedData([]byte("o"))
	keep := cipheron.WithTargetAssociatedData([]byte("o"))
	var enc bytes.Buffer
	if _, err := c.EncryptStream(ctx, "docs", &enc, bytes.NewReader(pt), int64(len(pt)), cipheron.WithSegmentSize(transport.MinSegmentSize), aad); err != nil {
		t.Fatal(err)
	}
	old, _ := segmentKeys(t, enc.Bytes())

	fake.SetWriteVersion("docs", "v2")
	reencryptOnly(fake, "docs")
	fake.SetBatchMaxItems(4) // eleven batches at least, up to three in flight
	var out bytes.Buffer
	n, err := c.ReEncryptStream(ctx, "docs", &out, bytes.NewReader(enc.Bytes()), aad, keep)
	if err != nil || n != int64(out.Len()) {
		t.Fatalf("ReEncryptStream: %d %v", n, err)
	}
	h, keys := segmentKeys(t, out.Bytes())
	// The object keeps its id (every segment keeps its binding: a migrator granted reencrypt alone re-encrypts it).
	if !allAre(keys, "v2") || !bytes.Equal(h.ObjectID, old.ObjectID) || h.SegmentSize != old.SegmentSize || h.Count != old.Count {
		t.Fatalf("the moved object: %+v %v", h, keys)
	}
	allOps(fake, "docs")
	if got, err := c.DecryptObject(ctx, "docs", out.Bytes(), aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("the streamed object, read whole: %v", err)
	}

	// A stream fails where its fault is: a spliced segment at its position, a cut, bytes after the end.
	_, segs, _ := transport.ParseSegmented(transport.Release(), enc.Bytes())
	other, _ := c.EncryptObject(ctx, "docs", pt, cipheron.WithSegmentSize(transport.MinSegmentSize), aad)
	_, osegs, _ := transport.ParseSegmented(transport.Release(), other)
	spliced, _ := transport.AppendSegmentedHeader(transport.Release(), nil, old)
	for i, s := range segs {
		if i == 30 {
			s = osegs[i]
		}
		spliced = transport.AppendSegment(spliced, s)
	}
	if _, err := c.ReEncryptStream(ctx, "docs", io.Discard, bytes.NewReader(spliced), aad, keep); !errors.Is(err, cipheron.ErrSegmented) ||
		!strings.Contains(err.Error(), "segment 30") {
		t.Fatalf("a spliced stream: %v", err)
	}
	cut, _ := transport.AppendSegmentedHeader(transport.Release(), nil, old)
	for _, s := range segs[:len(segs)-1] {
		cut = transport.AppendSegment(cut, s)
	}
	if _, err := c.ReEncryptStream(ctx, "docs", io.Discard, bytes.NewReader(cut), aad, keep); !errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("a stream cut short: %v", err)
	}
	if _, err := c.ReEncryptStream(ctx, "docs", io.Discard, bytes.NewReader(append(append([]byte{}, enc.Bytes()...), 0)), aad, keep); !errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("bytes after the last segment: %v", err)
	}
	// Over an object's bound, the target associated data is refused before anything is read or written.
	var none bytes.Buffer
	if n, err := c.ReEncryptStream(ctx, "docs", &none, bytes.NewReader(enc.Bytes()), aad,
		cipheron.WithTargetAssociatedData(make([]byte, transport.MaxObjectAssociatedDataLen+1))); n != 0 || none.Len() != 0 ||
		!errors.Is(err, cipheron.ErrAssociatedData) {
		t.Fatalf("a stream's target associated data over an object's bound: %d bytes written, %v", none.Len(), err)
	}
	wide := old
	wide.SegmentSize *= 2
	widened, _ := transport.AppendSegmentedHeader(transport.Release(), nil, wide)
	for _, s := range segs {
		widened = transport.AppendSegment(widened, s)
	}
	if _, err := c.ReEncryptStream(ctx, "docs", io.Discard, bytes.NewReader(widened), aad, keep); !errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("segments of another size: %v", err)
	}
}

func TestReEncryptForTenants(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "files", "customers")
	fake.MakePerTenant("files")
	fake.MakeDerived("customers")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("files", fake.Fingerprint("files")),
		cipheron.WithProfileFingerprint("customers", fake.Fingerprint("customers")))
	doc := []byte(`{"name":"Ada","ssn":"078-05-1120"}`)
	ptrs := []string{"/ssn"}
	pt := random(t, 3*transport.MinSegmentSize+1)
	seg := cipheron.WithSegmentSize(transport.MinSegmentSize)

	// Wrapped: the tenant's rows move to its new key (the service rotated it), under the migrator's reencrypt alone.
	k1, err := c.CreateTenantKey(ctx, "files", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	t1 := c.Tenant("files", "t_1", k1.Blob)
	encDoc, err := t1.EncryptJSONFields(ctx, doc, "u-1", ptrs)
	if err != nil {
		t.Fatal(err)
	}
	encObj, err := t1.EncryptObject(ctx, pt, seg)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := c.CreateTenantKey(ctx, "files", "t_1")
	if err != nil {
		t.Fatal(err)
	}
	reencryptOnly(fake, "files")
	movedDoc, err := t1.ReEncryptJSONFields(ctx, encDoc, "u-1", ptrs, k2.Blob)
	if err != nil {
		t.Fatal(err)
	}
	movedObj, err := t1.ReEncryptObject(ctx, encObj, k2.Blob)
	if err != nil {
		t.Fatal(err)
	}
	var streamed bytes.Buffer
	if _, err := t1.ReEncryptStream(ctx, &streamed, bytes.NewReader(encObj), k2.Blob); err != nil {
		t.Fatal(err)
	}
	want := "tenant-key:" + hex.EncodeToString(k2.KeyID)
	if k := fieldKey(t, movedDoc, "/ssn"); k != want {
		t.Fatalf("the moved field names %s, want %s", k, want)
	}
	for _, o := range [][]byte{movedObj, streamed.Bytes()} {
		if _, keys := segmentKeys(t, o); !allAre(keys, want) {
			t.Fatalf("the moved object's segments: %v, want %s", keys, want)
		}
	}
	// A wrapped profile needs the target blob.
	if _, err := t1.ReEncryptObject(ctx, encObj, nil); !errors.Is(err, cipheron.ErrTenantKey) {
		t.Fatalf("no target blob: %v", err)
	}
	allOps(fake, "files")
	t2 := c.Tenant("files", "t_1", k2.Blob)
	if got, err := t2.DecryptJSONFields(ctx, movedDoc, "u-1", ptrs); err != nil || string(got) != string(doc) {
		t.Fatalf("the moved field under the new key: %s %v", got, err)
	}
	for _, o := range [][]byte{movedObj, streamed.Bytes()} {
		if got, err := t2.DecryptObject(ctx, o); err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("the moved object under the new key: %v", err)
		}
	}

	// Derived: the tenant's rows move to the current master version.
	d := c.Tenant("customers", "t_1", nil)
	encDoc, err = d.EncryptJSONFields(ctx, doc, "u-1", ptrs)
	if err != nil {
		t.Fatal(err)
	}
	encObj, err = d.EncryptObject(ctx, pt, seg)
	if err != nil {
		t.Fatal(err)
	}
	fake.SetWriteVersion("customers", "v2")
	reencryptOnly(fake, "customers")
	if movedDoc, err = d.ReEncryptJSONFields(ctx, encDoc, "u-1", ptrs, nil); err != nil || fieldKey(t, movedDoc, "/ssn") != "v2" {
		t.Fatalf("a derived tenant's field: %v", err)
	}
	if movedObj, err = d.ReEncryptObject(ctx, encObj, nil); err != nil {
		t.Fatal(err)
	}
	streamed.Reset()
	if _, err := d.ReEncryptStream(ctx, &streamed, bytes.NewReader(encObj), nil); err != nil {
		t.Fatal(err)
	}
	for _, o := range [][]byte{movedObj, streamed.Bytes()} {
		if _, keys := segmentKeys(t, o); !allAre(keys, "v2") {
			t.Fatalf("a derived tenant's object: %v", keys)
		}
	}
	allOps(fake, "customers")
	if got, err := d.DecryptJSONFields(ctx, movedDoc, "u-1", ptrs); err != nil || string(got) != string(doc) {
		t.Fatalf("a derived tenant's moved field: %s %v", got, err)
	}
	// Another tenant's handle does not move them: its key does not open them.
	if _, err := c.Tenant("customers", "t_2", nil).ReEncryptObject(ctx, movedObj, nil); !errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("another tenant's handle: %v", err)
	}
}

// TestAVersionInTheAssociatedDataRefusesARollback: client-library.md's "Rollback: a version in the associated data",
// with the calls it names — the single calls, JSON fields and segmented objects, and their re-encryptions.
func TestAVersionInTheAssociatedDataRefusesARollback(t *testing.T) {
	ctx := ctxFor(t, 30*time.Second)
	fake := cipherontest.New(t, "invoices")
	c := newClient(t, fake.ServeSocket(t), cipheron.WithAnyServer(), cipheron.WithProfileFingerprint("invoices", fake.Fingerprint("invoices")))
	at := func(n int) []byte { return fmt.Appendf(nil, "invoices|inv-1|v=%d", n) }
	v := func(n int) cipheron.CallOption { return cipheron.WithAssociatedData(at(n)) }
	keep := func(n int) cipheron.CallOption { return cipheron.WithTargetAssociatedData(at(n)) }

	older, err := c.Encrypt(ctx, "invoices", []byte("total 100"), v(7))
	if err != nil {
		t.Fatal(err)
	}
	current, err := c.Encrypt(ctx, "invoices", []byte("total 90"), v(8))
	if err != nil {
		t.Fatal(err)
	}
	// The trusted number is 8: the current value reads, the older one put back does not — not as a missing associated
	// data, as a ciphertext that does not decrypt.
	if pt, err := c.Decrypt(ctx, "invoices", current, v(8)); err != nil || string(pt) != "total 90" {
		t.Fatalf("the current value: %q %v", pt, err)
	}
	if _, err := c.Decrypt(ctx, "invoices", older, v(8)); !errors.Is(err, cipheron.ErrInvalidInput) || errors.Is(err, cipheron.ErrAssociatedData) {
		t.Fatalf("an older value put back: %v", err)
	}
	// A re-encryption (a rotation's sweep) keeps the number bound.
	fake.SetWriteVersion("invoices", "v2")
	moved, err := c.ReEncrypt(ctx, "invoices", current, v(8), keep(8))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, "invoices", moved, v(8)); err != nil || string(pt) != "total 90" {
		t.Fatalf("the re-encrypted value: %q %v", pt, err)
	}

	// JSON fields: the number is bound into every field of the call.
	ptrs := []string{"/total"}
	f7, err := c.EncryptJSONFields(ctx, "invoices", []byte(`{"total":100}`), "inv-1", ptrs, v(7))
	if err != nil {
		t.Fatal(err)
	}
	f8, err := c.EncryptJSONFields(ctx, "invoices", []byte(`{"total":90}`), "inv-1", ptrs, v(8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecryptJSONFields(ctx, "invoices", f7, "inv-1", ptrs, v(8)); !errors.Is(err, cipheron.ErrInvalidInput) {
		t.Fatalf("an older document put back: %v", err)
	}
	mf, err := c.ReEncryptJSONFields(ctx, "invoices", f8, "inv-1", ptrs, v(8), keep(8))
	if err != nil {
		t.Fatal(err)
	}
	if doc, err := c.DecryptJSONFields(ctx, "invoices", mf, "inv-1", ptrs, v(8)); err != nil || string(doc) != `{"total":90}` {
		t.Fatalf("the re-encrypted document: %s %v", doc, err)
	}

	// Segmented objects: into every segment.
	o7, err := c.EncryptObject(ctx, "invoices", []byte("scan of version 7"), v(7))
	if err != nil {
		t.Fatal(err)
	}
	o8, err := c.EncryptObject(ctx, "invoices", []byte("scan of version 8"), v(8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecryptObject(ctx, "invoices", o7, v(8)); !errors.Is(err, cipheron.ErrSegmented) {
		t.Fatalf("an older object put back: %v", err)
	}
	mo, err := c.ReEncryptObject(ctx, "invoices", o8, v(8), keep(8))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.DecryptObject(ctx, "invoices", mo, v(8)); err != nil || string(pt) != "scan of version 8" {
		t.Fatalf("the re-encrypted object: %q %v", pt, err)
	}
}
