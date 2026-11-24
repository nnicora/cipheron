package cipheron

// batch.go — associated data, the batch operations, segmented objects, the cross-profile ReEncrypt and the key
// statement, as this package offers them.

import (
	"context"
	"time"

	"github.com/nnicora/cipheron/internal/client"
)

// CallOption is an option of one call: Encrypt, Decrypt, ReEncrypt, ReEncryptAcross and the object calls, and the
// tenant forms.
type CallOption = client.CallOption

// WithAssociatedData binds associated data — context, not a secret: a row's primary key, a record type, a column
// name; 1 to 64 KiB — into the ciphertext Encrypt makes (format 5, or 6 in a wrapped profile), and is the associated
// data a ciphertext given to Decrypt or ReEncrypt was made with. cipheron stores none of it: give it again at every
// Decrypt. A ciphertext made with it never decrypts without it, or with other associated data — so a ciphertext
// copied from one row to another (whose key is the associated data) does not decrypt there.
func WithAssociatedData(aad []byte) CallOption { return client.WithAssociatedData(aad) }

// WithTargetAssociatedData is the associated data a re-encryption makes the NEW ciphertext with: ReEncrypt,
// ReEncryptAcross, their tenant forms, and the caller's part of ReEncryptJSONFields, ReEncryptObject and
// ReEncryptStream. It must be WithAssociatedData's, byte for byte: a re-encryption keeps the binding. Without it, with
// it alone, or with other bytes, the call is refused before anything is sent (ErrAssociatedData, which is
// ErrInvalidInput), so a binding is never dropped or changed by a re-encryption. Moving a value to another row or
// binding is a Decrypt and an Encrypt, which the caller's entry must be granted.
func WithTargetAssociatedData(aad []byte) CallOption { return client.WithTargetAssociatedData(aad) }

// WithSegmentSize is EncryptObject's segment size in bytes (1 KiB to 16 MiB; 64 KiB by default).
func WithSegmentSize(n int) CallOption { return client.WithSegmentSize(n) }

// BatchItem is one item of a batch: Data is the plaintext (EncryptBatch) or the ciphertext (DecryptBatch,
// ReEncryptBatch); AssociatedData the associated data it is or was made with; ToAssociatedData the new ciphertext's
// (ReEncryptBatch: equal to AssociatedData, as WithTargetAssociatedData is).
type BatchItem = client.BatchItem

// BatchResult is one item's result: Value (the ciphertext, or the plaintext), or Err — that item's own failure,
// mapped as the single call's error would be (ErrInvalidInput, ErrKeyVersionUnavailable, ErrAssociatedData, …).
type BatchResult = client.BatchResult

// TenantKeyRef names one tenant key blob for RewrapTenantKeyBatch.
type TenantKeyRef = client.TenantKeyRef

// TenantKeyResult is one item of RewrapTenantKeyBatch: the rewrapped key, or the item's own failure.
type TenantKeyResult struct {
	Key TenantKey
	Err error
}

// mapResults maps every item error.
func mapResults(ctx context.Context, rs []BatchResult) []BatchResult {
	for i := range rs {
		if rs[i].Err != nil {
			rs[i].Err = mapErr(ctx, rs[i].Err)
		}
	}
	return rs
}

// EncryptBatch encrypts items in the shared profile in one request (one auth, one answer signature), each item with
// its own result in order. cipheron bounds a batch (batch.maxItems, 128 by default; batch.maxBytes, by default room for one segment of the largest size): one over
// a limit is refused whole, ErrInvalidInput, and BatchLimits reads the limits from the error. A failure of the whole
// request (permission, unavailable, busy) is the error; an item's own failure is its BatchResult.Err.
func (c *Client) EncryptBatch(ctx context.Context, profile string, items []BatchItem) ([]BatchResult, error) {
	rs, err := c.c.EncryptBatch(ctx, profile, items)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// DecryptBatch decrypts items (ciphertexts of the shared profile, each with the associated data it was made with)
// in one request, as EncryptBatch.
func (c *Client) DecryptBatch(ctx context.Context, profile string, items []BatchItem) ([]BatchResult, error) {
	rs, err := c.c.DecryptBatch(ctx, profile, items)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// ReEncryptBatch re-encrypts items (ciphertexts of the shared profile) under the current keys in one request, as
// EncryptBatch; the plaintexts never leave cipheron. An item whose ToAssociatedData is not its AssociatedData refuses
// the whole batch before anything is sent (ErrAssociatedData).
func (c *Client) ReEncryptBatch(ctx context.Context, profile string, items []BatchItem) ([]BatchResult, error) {
	rs, err := c.c.ReEncryptBatch(ctx, profile, items)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// RewrapTenantKeyBatch rewraps tenant key blobs of a wrapped profile — of any tenants — in one request (operation
// provision), each checked as RewrapTenantKey's answer is. A tenant the caller's entry is not allowed, or revoked,
// is that item's ErrPermissionDenied. Every blob is checked before anything is sent: one that is not its item's
// tenant's key in the profile refuses the whole call (ErrTenantKey), and nothing is rewrapped.
func (c *Client) RewrapTenantKeyBatch(ctx context.Context, profile string, keys []TenantKeyRef) ([]TenantKeyResult, error) {
	rs, err := c.c.RewrapTenantKeyBatch(ctx, profile, keys)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	out := make([]TenantKeyResult, len(rs))
	for i, r := range rs {
		if r.Err != nil {
			out[i].Err = mapErr(ctx, r.Err)
			continue
		}
		out[i].Key = tenantKey(r.Key)
	}
	return out, nil
}

// EncryptBatch is Client.EncryptBatch for the tenant.
func (t *Tenant) EncryptBatch(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
	rs, err := t.t.EncryptBatch(ctx, items)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// DecryptBatch is Client.DecryptBatch for the tenant.
func (t *Tenant) DecryptBatch(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
	rs, err := t.t.DecryptBatch(ctx, items)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// ReEncryptBatch is Client.ReEncryptBatch for the tenant: wrapped, every item moves to the blob to (as
// Tenant.ReEncrypt); derived, to is nil.
func (t *Tenant) ReEncryptBatch(ctx context.Context, items []BatchItem, to []byte) ([]BatchResult, error) {
	rs, err := t.t.ReEncryptBatch(ctx, items, to)
	return mapResults(ctx, rs), mapErr(ctx, err)
}

// BatchLimits reads cipheron's batch limits (maxItems, maxBytes) from the error of a batch it refused as over them;
// false for any other error.
func BatchLimits(err error) (maxItems int, maxBytes int64, ok bool) { return client.BatchLimits(err) }

// EncryptObject encrypts an object of any size in the shared profile as a SEGMENTED object: cut into segments
// (WithSegmentSize), each encrypted by cipheron through EncryptBatch with associated data that names the object (a
// random id), the segment's position and whether it is the last (and WithAssociatedData's, when given). Store the
// result whole. DecryptObject refuses an object whose segments were reordered, dropped (truncation), added or taken
// from another object (ErrSegmented).
func (c *Client) EncryptObject(ctx context.Context, profile string, plaintext []byte, opts ...CallOption) ([]byte, error) {
	out, err := c.c.EncryptObject(ctx, profile, plaintext, opts...)
	return out, mapErr(ctx, err)
}

// DecryptObject decrypts a segmented object of the shared profile (EncryptObject), with the associated data it was
// made with. Any segment that does not decrypt as its own position's fails the whole object: ErrSegmented (which is
// ErrInvalidInput), and nothing of it is returned.
func (c *Client) DecryptObject(ctx context.Context, profile string, object []byte, opts ...CallOption) ([]byte, error) {
	out, err := c.c.DecryptObject(ctx, profile, object, opts...)
	return out, mapErr(ctx, err)
}

// ReEncryptObject has cipheron re-encrypt a segmented object of the shared profile (EncryptObject's or EncryptStream's)
// under the profile's current keys, its segments through ReEncryptBatch, and returns the object again: the same object
// id, segment size and count, every segment keeping its binding. The plaintext never leaves cipheron — the caller's
// entry needs the reencrypt operation only, and nothing this returns is a plaintext — the migration sweep a key
// rotation needs (KeyID names each segment's key). WithAssociatedData is the stored object's associated data, and
// WithTargetAssociatedData must be the same (ErrAssociatedData otherwise).
// WithSegmentSize, when given, must be the object's own (ErrInvalidInput). A segment that does not decrypt as its own
// position's, or holds another size than its place holds, fails the whole object (ErrSegmented), as in DecryptObject;
// nothing is returned unless every segment was re-encrypted. The object is held in memory twice; ReEncryptStream holds
// a few batches of it.
func (c *Client) ReEncryptObject(ctx context.Context, profile string, object []byte, opts ...CallOption) ([]byte, error) {
	out, err := c.c.ReEncryptObject(ctx, profile, object, opts...)
	return out, mapErr(ctx, err)
}

// EncryptObject is Client.EncryptObject for the tenant.
func (t *Tenant) EncryptObject(ctx context.Context, plaintext []byte, opts ...CallOption) ([]byte, error) {
	out, err := t.t.EncryptObject(ctx, plaintext, opts...)
	return out, mapErr(ctx, err)
}

// DecryptObject is Client.DecryptObject for the tenant.
func (t *Tenant) DecryptObject(ctx context.Context, object []byte, opts ...CallOption) ([]byte, error) {
	out, err := t.t.DecryptObject(ctx, object, opts...)
	return out, mapErr(ctx, err)
}

// ReEncryptObject is Client.ReEncryptObject for the tenant: in a wrapped profile every segment moves to the tenant key
// blob to (as Tenant.ReEncrypt: the tenant's new key, or the handle's own blob); in a derived one to is nil.
func (t *Tenant) ReEncryptObject(ctx context.Context, object, to []byte, opts ...CallOption) ([]byte, error) {
	out, err := t.t.ReEncryptObject(ctx, object, to, opts...)
	return out, mapErr(ctx, err)
}

// Scope names where a ciphertext is, for ReEncryptAcross: a profile, and in a perTenant profile the tenant — with its
// tenant key blob in a wrapped one (the blob the ciphertext was made under; for the target, the blob to make it
// under).
type Scope = client.ReEncryptAcrossScope

// ReEncryptAcross moves a ciphertext from one profile to ANOTHER profile the same cipheron serves — a profile whose
// identity must change, a tenancy change, a move between residency or algorithm generations — without the plaintext
// leaving cipheron. The caller needs operation export in the source profile and import in the target (and their
// tenants) — reencrypt is within a profile only, and a migration needs neither decrypt nor encrypt —, and retenant in
// the source profile too when the move changes the tenant (another tenant, or between a shared and a perTenant
// profile, as a tenancy change does); its request key signs for both. The answer is signed by both profiles' response keys and checked against both identities (pinned
// or first seen). WithAssociatedData is the stored ciphertext's associated data, and WithTargetAssociatedData must be
// the same (ErrAssociatedData otherwise): the move keeps the binding. A refusal in either profile is
// ErrPermissionDenied. Import is a write grant into the target: whatever its holder can export becomes the target's.
func (c *Client) ReEncryptAcross(ctx context.Context, from, to Scope, ciphertext []byte, opts ...CallOption) ([]byte, error) {
	ct, err := c.c.ReEncryptAcross(ctx, from, to, ciphertext, opts...)
	return ct, mapErr(ctx, err)
}

// KeyStatement is a profile's key statement: its identity, tenancy, key-context digest and signing keys with their
// states and algorithms, issued by cipheron at IssuedAt and signed by its response key WITHOUT a nonce — so it can be
// published and checked offline by anyone holding the profile's fingerprint (ImportKeyStatement), viewed as a JWKS
// (JWKS), and used to verify signatures with the states honoured (Verify for a shared profile's, VerifyTenant for a
// derived profile's; each refuses a statement of the other tenancy with ErrTenancy). It proves no freshness: a
// verifier bounds its age.
type KeyStatement = client.KeyStatement

// KeyStatement is the profile's key statement, verified by this Client with the profile's keys, which it asks cipheron
// for now. Export it to publish it. It is the most recent statement whose signing keys are the list this Client
// holds, states included, while that statement is younger than WithKeysMaxAge: a statement that lists as usable a key
// this Client holds revoked (a replica that lags the revocation answers one) is never handed out. Without an agreeing
// statement it is ErrSigningKeyRevoked (the statements answered would un-revoke a key) or ErrKeysStale.
func (c *Client) KeyStatement(ctx context.Context, profile string) (*KeyStatement, error) {
	st, err := c.c.KeyStatement(ctx, profile)
	return st, mapErr(ctx, err)
}

// ImportKeyStatement reads a published statement (KeyStatement.Export) and verifies it offline, without cipheron,
// for profile against fingerprint — the profile's fingerprint the verifier PINNED (never the one the document
// carries): the identity inside must have it, and the signature must be its response key's. It refuses a statement
// issued more than maxAge ago; maxAge must be positive (0 is refused: ImportKeyStatementAnyAge is the call without
// an age check). Any failure is ErrKeyStatement (which is ErrInvalidInput).
func ImportKeyStatement(exported []byte, profile, fingerprint string, maxAge time.Duration) (*KeyStatement, error) {
	st, err := client.ImportKeyStatement(exported, profile, fingerprint, maxAge, time.Now())
	return st, mapErr(context.Background(), err)
}

// ImportKeyStatementAnyAge is ImportKeyStatement without the age check — a statement of any age that verifies is
// accepted, one replayed after a revocation included: only for a verifier with another way to know the statement is
// current. Any failure is ErrKeyStatement.
func ImportKeyStatementAnyAge(exported []byte, profile, fingerprint string) (*KeyStatement, error) {
	st, err := client.ImportKeyStatementAnyAge(exported, profile, fingerprint)
	return st, mapErr(context.Background(), err)
}
