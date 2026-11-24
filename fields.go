package cipheron

// fields.go — the client helpers over the batch calls: JSON field encryption and the streaming forms of the
// segmented objects.

import (
	"context"
	"io"

	"github.com/nnicora/cipheron/wire/transport"
)

// EncryptJSONFields encrypts the fields of doc (one JSON value) that pointers name — JSON Pointers (RFC 6901):
// "/card/number", "/contacts/0/email" — in the shared profile, in as few batches as cipheron's limits allow, and
// returns the document with each such value replaced by a string holding its ciphertext (transport.JSONFieldPrefix
// and base64). A field's plaintext is its value as compact JSON, of any type, so DecryptJSONFields gives it back as it
// was.
//
// Each field is bound, by associated data, to its pointer AND to recordID — the record's own identity (its primary
// key, a document id; 1 to 1024 bytes): a field's ciphertext moved to another place in the document, or into
// another record, does not decrypt. WithAssociatedData adds the caller's own. Every pointer must name a value; none
// may repeat or lie inside another (ErrJSONField). The rest of the document is unchanged — written again compact,
// with object keys in sorted order and numbers as written.
func (c *Client) EncryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	out, err := c.c.EncryptJSONFields(ctx, profile, doc, recordID, pointers, opts...)
	return out, mapErr(ctx, err)
}

// DecryptJSONFields decrypts the fields pointers name in doc (EncryptJSONFields' output) with the record id and the
// associated data they were made with. A value at one of pointers that is not an encrypted field — a field put back
// in clear — is refused (ErrJSONField), never passed through; a field moved from another place or record does not
// decrypt (ErrInvalidInput). Nothing is returned unless every field decrypted.
func (c *Client) DecryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	out, err := c.c.DecryptJSONFields(ctx, profile, doc, recordID, pointers, opts...)
	return out, mapErr(ctx, err)
}

// ReEncryptJSONFields has cipheron re-encrypt the encrypted fields pointers name in doc (EncryptJSONFields' output)
// under the profile's current keys, in as few batches as cipheron's limits allow (ReEncryptBatch), and returns the
// document with each field's new ciphertext in its place. The plaintexts never leave cipheron: the caller's entry
// needs the reencrypt operation only, and nothing this returns is a plaintext — the migration sweep a key rotation
// needs, reading each field's key with JSONFieldKeyID first. Each field is decrypted with the record id, the pointer
// and WithAssociatedData's associated data it was made with, and made again bound to the same: the same record and
// pointer, and WithTargetAssociatedData, which must be WithAssociatedData's (ErrAssociatedData before anything is sent
// otherwise) — a re-encryption keeps the binding. The input is checked as
// DecryptJSONFields checks it (a field in clear is ErrJSONField; a field moved from another place or record does not
// decrypt, ErrInvalidInput). Nothing is returned unless every field was re-encrypted.
func (c *Client) ReEncryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	out, err := c.c.ReEncryptJSONFields(ctx, profile, doc, recordID, pointers, opts...)
	return out, mapErr(ctx, err)
}

// JSONFieldPrefix opens the value of an encrypted field in a document EncryptJSONFields wrote: "cipheron:v1:", then
// the ciphertext's standard base64: the prefix of the version this library writes. Whether a value is an encrypted
// field, of any version this library reads, is IsJSONField.
const JSONFieldPrefix = transport.JSONFieldPrefix

// IsJSONField reports whether value is an encrypted field's value: a string opening with exactly the prefix of a
// version this library reads ("cipheron:v1:"). EncryptJSONFields refuses to encrypt such a value again.
func IsJSONField(value string) bool { return transport.IsJSONField(transport.Release(), value) }

// JSONFieldKeyID names the key an encrypted field was made under: KeyID of the ciphertext its value (the string at
// one of EncryptJSONFields' pointers) holds. It runs locally and decrypts nothing — a sweep reads it to find the
// fields ReEncryptJSONFields must move — and the header it reads is authenticated only when cipheron opens the
// ciphertext. A value that is not an encrypted field (not JSONFieldPrefix and base64) is ErrJSONField; one that holds
// no cipheron ciphertext, ErrInvalidInput (both are ErrInvalidInput).
func JSONFieldKeyID(value string) (CiphertextKey, error) {
	ct, err := transport.DecodeJSONField(transport.Release(), value)
	if err != nil {
		return CiphertextKey{}, mapErr(context.Background(), err)
	}
	return KeyID(ct)
}

// EncryptJSONFields is Client.EncryptJSONFields for the tenant.
func (t *Tenant) EncryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	out, err := t.t.EncryptJSONFields(ctx, doc, recordID, pointers, opts...)
	return out, mapErr(ctx, err)
}

// DecryptJSONFields is Client.DecryptJSONFields for the tenant.
func (t *Tenant) DecryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	out, err := t.t.DecryptJSONFields(ctx, doc, recordID, pointers, opts...)
	return out, mapErr(ctx, err)
}

// ReEncryptJSONFields is Client.ReEncryptJSONFields for the tenant: in a wrapped profile every field moves to the tenant
// key blob to (as Tenant.ReEncrypt: the tenant's new key, or the handle's own blob); in a derived one to is nil.
func (t *Tenant) ReEncryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string, to []byte,
	opts ...CallOption) ([]byte, error) {
	out, err := t.t.ReEncryptJSONFields(ctx, doc, recordID, pointers, to, opts...)
	return out, mapErr(ctx, err)
}

// EncryptStream is EncryptObject over a stream: it reads exactly size bytes from src (the size is needed up front:
// the object's header names its segment count, and its last segment is made final) and writes the segmented object
// to dst as it goes, with up to three batches of segments in memory at a time (in flight to cipheron at once), never
// the whole object. It returns the bytes written to dst. A src shorter or longer than size is ErrInvalidInput. On any
// error, discard what was written to dst.
func (c *Client) EncryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, size int64,
	opts ...CallOption) (int64, error) {
	n, err := c.c.EncryptStream(ctx, profile, dst, src, size, opts...)
	return n, mapErr(ctx, err)
}

// DecryptStream is DecryptObject over a stream: it reads a segmented object from src and writes its plaintext to dst
// a batch of segments at a time, returning the plaintext bytes written. Every segment written was decrypted as its
// own position's in this object, but an object truncated, extended or modified further on fails only when that point
// is reached (ErrSegmented), AFTER the plaintext before it was written: on any error, discard what was written. When
// nothing may be released before the whole object is verified, use DecryptObject.
func (c *Client) DecryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	n, err := c.c.DecryptStream(ctx, profile, dst, src, opts...)
	return n, mapErr(ctx, err)
}

// EncryptStream is Client.EncryptStream for the tenant.
func (t *Tenant) EncryptStream(ctx context.Context, dst io.Writer, src io.Reader, size int64, opts ...CallOption) (int64, error) {
	n, err := t.t.EncryptStream(ctx, dst, src, size, opts...)
	return n, mapErr(ctx, err)
}

// DecryptStream is Client.DecryptStream for the tenant.
func (t *Tenant) DecryptStream(ctx context.Context, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	n, err := t.t.DecryptStream(ctx, dst, src, opts...)
	return n, mapErr(ctx, err)
}

// ReEncryptStream is ReEncryptObject over a stream: it reads a segmented object from src and writes the re-encrypted
// object to dst as it goes, with up to three batches of segments in memory at a time (in flight to cipheron at once),
// never the whole object, and returns the bytes written to dst. No plaintext reaches the caller: the entry needs the
// reencrypt operation only. A segment that does not re-encrypt as its own position's, or holds another size than its
// place holds, fails the stream when it is reached (ErrSegmented), and so do bytes after the last segment: on any
// error, discard what was written to dst. WithTargetAssociatedData must be WithAssociatedData's, as ReEncryptObject's
// (ErrAssociatedData before anything is read or sent).
func (c *Client) ReEncryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	n, err := c.c.ReEncryptStream(ctx, profile, dst, src, opts...)
	return n, mapErr(ctx, err)
}

// ReEncryptStream is Client.ReEncryptStream for the tenant: in a wrapped profile every segment moves to the tenant key
// blob to (as Tenant.ReEncrypt); in a derived one to is nil.
func (t *Tenant) ReEncryptStream(ctx context.Context, dst io.Writer, src io.Reader, to []byte, opts ...CallOption) (int64, error) {
	n, err := t.t.ReEncryptStream(ctx, dst, src, to, opts...)
	return n, mapErr(ctx, err)
}
