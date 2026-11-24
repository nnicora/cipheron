package client

// batch.go — the batch operations (one request, one nonce, one auth and one response signature for many items, each
// with its own result) and the cross-profile ReEncrypt.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/internal/zeroize"
	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// BatchItem is one item of a batch: Data is the plaintext (EncryptBatch) or the ciphertext (DecryptBatch,
// ReEncryptBatch); AssociatedData is the associated data it is made with (EncryptBatch) or was made with
// (DecryptBatch, ReEncryptBatch); ToAssociatedData is the new ciphertext's (ReEncryptBatch). Empty: none.
type BatchItem struct {
	Data, AssociatedData, ToAssociatedData []byte
}

// BatchResult is one item's result: Value — the ciphertext, or the plaintext — or Err, the item's own failure (the
// status cipheron answered for it: a ciphertext that does not decrypt, a key version not listed, associated data
// that does not match). A failure of the whole batch is the call's error, not an item's.
type BatchResult struct {
	Value []byte
	Err   error
}

// itemErr is an item error as a status: its code and message, with its ErrorInfo reason when it carries one — what
// the single operation would have answered.
func itemErr(e *cipheronv1.ItemError) error {
	st := status.New(codes.Code(e.GetCode()), e.GetMessage())
	if e.GetReason() != "" {
		if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: e.GetReason(), Domain: transport.ErrorDomain}); err == nil {
			st = d
		}
	}
	return st.Err()
}

// checkItemError refuses an item error that could not be an item's (a code of OK, or one the server answers the
// whole batch with).
func checkItemError(s scope, e *cipheronv1.ItemError) error {
	switch codes.Code(e.GetCode()) {
	case codes.OK, codes.Unavailable, codes.ResourceExhausted, codes.Internal, codes.Unknown, codes.FailedPrecondition:
		return fmt.Errorf("%w: a batch item error for %s with code %d", ErrBadResponse, s.who(), e.GetCode())
	}
	return nil
}

// itemErrorAlone checks error item i of an AUTHENTICATED batch answer. A result field beside the error (result: the
// fields a result of the operation has) is not covered by the response signature — the item's digest is the error's
// (transport.ItemErrorDigest) — so it is not cipheron's answer: ErrServerIdentity. An error code no item is answered
// with is covered: ErrBadResponse (checkItemError).
func itemErrorAlone(s scope, i int, e *cipheronv1.ItemError, result ...[]byte) error {
	for _, f := range result {
		if len(f) > 0 {
			return identityFailure(fmt.Errorf("batch item %d answered for %s is an error that also carries a result, "+
				"which the response signature does not cover", i, s.who()))
		}
	}
	if err := checkItemError(s, e); err != nil {
		return fmt.Errorf("batch item %d: %w", i, err)
	}
	return nil
}

// verifyBatch authenticates a batch answer of n results before anything in it is read, then holds it to the sent
// items. n is bounded first (transport.MaxBatchItems: no batch holds more, so nothing past it is hashed — an answer
// over it is not shown to be cipheron's, ErrServerIdentity). The response signature is then checked over the results
// AS RECEIVED (itemDigest(i) of each): a result dropped, added or changed in the path fails it (ErrServerIdentity,
// which the observer counts). Only then must there be one result per item sent: a signed answer with another count
// is ErrBadResponse, a defect.
func (c *Client) verifyBatch(ctx context.Context, s scope, op transport.Operation, nonce []byte,
	auth *cipheronv1.RequestAuth, reqDigest [sha256.Size]byte, sig []byte, n, sent int,
	itemDigest func(i int) [sha256.Size]byte,
) error {
	if n > transport.MaxBatchItems {
		return identityFailure(fmt.Errorf("the %s answer for %s holds %d results; no batch holds more than %d", op,
			s.who(), n, transport.MaxBatchItems))
	}
	rdigests := make([][sha256.Size]byte, n)
	for i := range rdigests {
		rdigests[i] = itemDigest(i)
	}
	if err := c.verifyResponse(ctx, s.profile, s.k, op, nonce, auth, reqDigest, transport.BatchDigest(rdigests), sig); err != nil {
		return err
	}
	if n != sent {
		return fmt.Errorf("%w: %d results for a batch of %d items for %s", ErrBadResponse, n, sent, s.who())
	}
	return nil
}

// batchFits is the size check of a batch before anything is sealed.
func (c *Client) batchFits(profile string, items []BatchItem, extra int) error {
	n := extra
	for _, it := range items {
		n += len(it.Data) + len(it.AssociatedData) + len(it.ToAssociatedData) + maxCiphertextOverhead() + 16
	}
	return c.fits(profile, n)
}

func checkBatchItems(items []BatchItem) error {
	if len(items) == 0 || len(items) > transport.MaxBatchItems {
		return fmt.Errorf("cipheron: a batch holds 1 to %d items, not %d", transport.MaxBatchItems, len(items))
	}
	for _, it := range items {
		if len(it.AssociatedData) > transport.MaxAssociatedDataLen || len(it.ToAssociatedData) > transport.MaxAssociatedDataLen {
			return fmt.Errorf("%w: associated data is at most %d bytes", ErrAssociatedData, transport.MaxAssociatedDataLen)
		}
	}
	return nil
}

// checkReEncryptItems refuses, before anything is sent, a ReEncryptBatch whose item's ToAssociatedData is not its
// AssociatedData, byte for byte (transport.CheckReEncryptAssociatedData, as reencryptOpts for the single calls): one
// that drops the binding (transport.ErrTargetAssociatedData) or changes it (transport.ErrAssociatedDataChanged) — the
// whole batch, as the other item checks do. A re-encryption keeps the binding; a re-binding is a decrypt and an
// encrypt. cipheron refuses such an item on its own (its ItemError).
func checkReEncryptItems(items []BatchItem) error {
	for i, it := range items {
		if err := transport.CheckReEncryptAssociatedData(it.AssociatedData, it.ToAssociatedData); err != nil {
			return fmt.Errorf("%w: batch item %d: give it ToAssociatedData equal to its AssociatedData (a re-encryption "+
				"keeps the binding; a re-binding is a decrypt and an encrypt)", err, i)
		}
	}
	return nil
}

func (c *Client) encryptBatchOnce(ctx context.Context, s scope, items []BatchItem) ([]BatchResult, error) {
	req := &cipheronv1.EncryptBatchRequest{Profile: s.profile, Tenant: s.tenant, TenantKey: s.blob,
		RequestNonce: newNonce()}
	digests := make([][sha256.Size]byte, len(items))
	req.Items = make([]*cipheronv1.EncryptBatchItem, len(items))
	// Each item sealed to cipheron's key on its own (parallel.go): the first failure in index order is the error.
	if err := eachItem(len(items), func(i int) error {
		it := items[i]
		enc, sealed, err := c.seal(s, transport.OpEncrypt, it.Data)
		if err != nil {
			return err
		}
		req.Items[i] = &cipheronv1.EncryptBatchItem{Enc: enc, SealedPlaintext: sealed, AssociatedData: it.AssociatedData}
		digests[i] = transport.EncryptDigestAAD(enc, sealed, s.tenant, s.blob, it.AssociatedData)
		return nil
	}); err != nil {
		return nil, err
	}
	reqDigest := transport.BatchDigest(digests)
	auth, err := c.auth(s.profile, transport.OpEncryptBatch, req.GetRequestNonce(), reqDigest)
	if err != nil {
		return nil, err
	}
	req.Auth = auth
	resp, err := c.pick().EncryptBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	res := resp.GetResults()
	if err := c.verifyBatch(ctx, s, transport.OpEncryptBatch, req.GetRequestNonce(), auth, reqDigest, resp.GetResponseSignature(),
		len(res), len(items), func(i int) [sha256.Size]byte {
			if e := res[i].GetError(); e != nil {
				return transport.ItemErrorDigest(e.GetCode(), e.GetReason(), e.GetMessage())
			}
			return transport.ItemResultDigest(res[i].GetCiphertext())
		}); err != nil {
		return nil, err
	}
	var keyID []byte
	if s.h != nil {
		keyID = s.h.KeyID
	}
	out := make([]BatchResult, len(res))
	for i, r := range res {
		if e := r.GetError(); e != nil {
			if err := itemErrorAlone(s, i, e, r.GetCiphertext()); err != nil {
				return nil, err
			}
			out[i].Err = itemErr(e)
			continue
		}
		if err := c.checkCiphertext(s, r.GetCiphertext(), len(items[i].Data), keyID, len(items[i].AssociatedData) > 0); err != nil {
			return nil, err
		}
		out[i].Value = r.GetCiphertext()
	}
	return out, nil
}

func (c *Client) decryptBatchOnce(ctx context.Context, s scope, items []BatchItem) ([]BatchResult, error) {
	for _, it := range items {
		if _, err := parseCiphertext(s, it.Data, it.AssociatedData); err != nil {
			return nil, err
		}
	}
	sk, err := transport.NewOneTimeKey()
	if err != nil {
		return nil, err
	}
	recipient := sk.PublicKey().Bytes()
	req := &cipheronv1.DecryptBatchRequest{Profile: s.profile, RecipientPublicKey: recipient, Tenant: s.tenant,
		TenantKey: s.blob, RequestNonce: newNonce()}
	digests := make([][sha256.Size]byte, len(items))
	for i, it := range items {
		req.Items = append(req.Items, &cipheronv1.DecryptBatchItem{Ciphertext: it.Data, AssociatedData: it.AssociatedData})
		digests[i] = transport.DecryptDigestAAD(recipient, it.Data, s.tenant, s.blob, it.AssociatedData)
	}
	reqDigest := transport.BatchDigest(digests)
	auth, err := c.auth(s.profile, transport.OpDecryptBatch, req.GetRequestNonce(), reqDigest)
	if err != nil {
		return nil, err
	}
	req.Auth = auth
	resp, err := c.pick().DecryptBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	res := resp.GetResults()
	if err := c.verifyBatch(ctx, s, transport.OpDecryptBatch, req.GetRequestNonce(), auth, reqDigest, resp.GetResponseSignature(),
		len(res), len(items), func(i int) [sha256.Size]byte {
			if e := res[i].GetError(); e != nil {
				return transport.ItemErrorDigest(e.GetCode(), e.GetReason(), e.GetMessage())
			}
			return transport.ItemResultDigest(recipient, res[i].GetEnc(), res[i].GetSealedPlaintext())
		}); err != nil {
		return nil, err
	}
	out := make([]BatchResult, len(res))
	// Each plaintext opened on its own (parallel.go): the first bad item in index order is the error, as in order.
	if err := eachItem(len(res), func(i int) error {
		r := res[i]
		if e := r.GetError(); e != nil {
			if err := itemErrorAlone(s, i, e, r.GetEnc(), r.GetSealedPlaintext()); err != nil {
				return err
			}
			out[i].Err = itemErr(e)
			return nil
		}
		pt, err := transport.OpenResponsePayload(transport.Release(), sk, s.profile, transport.OpDecrypt, s.tenant, r.GetEnc(),
			r.GetSealedPlaintext())
		if err != nil {
			return fmt.Errorf("%w: the plaintext of batch item %d for %s: %w", ErrBadResponse, i, s.who(), err)
		}
		out[i].Value = pt
		return nil
	}); err != nil {
		// The answer is refused whole: the plaintexts already opened are wiped, not merely dropped.
		for i := range out {
			zeroize.Bytes(out[i].Value)
		}
		return nil, err
	}
	return out, nil
}

func (c *Client) reencryptBatchOnce(ctx context.Context, s scope, items []BatchItem, to []byte,
	toHeader *transport.TenantKeyHeader,
) ([]BatchResult, error) {
	sizes := make([]int, len(items))
	for i, it := range items {
		kid, err := parseCiphertext(s, it.Data, it.AssociatedData)
		if err != nil {
			return nil, err
		}
		sizes[i] = len(it.Data) - kid.Overhead()
	}
	req := &cipheronv1.ReEncryptBatchRequest{Profile: s.profile, Tenant: s.tenant, TenantKey: s.blob, ToTenantKey: to,
		RequestNonce: newNonce()}
	digests := make([][sha256.Size]byte, len(items))
	for i, it := range items {
		req.Items = append(req.Items, &cipheronv1.ReEncryptBatchItem{Ciphertext: it.Data, AssociatedData: it.AssociatedData,
			ToAssociatedData: it.ToAssociatedData})
		digests[i] = transport.ReEncryptDigestExt(it.Data, s.tenant, s.blob, to, transport.ReEncryptExt{
			AssociatedData: it.AssociatedData, ToAssociatedData: it.ToAssociatedData})
	}
	reqDigest := transport.BatchDigest(digests)
	auth, err := c.auth(s.profile, transport.OpReEncryptBatch, req.GetRequestNonce(), reqDigest)
	if err != nil {
		return nil, err
	}
	req.Auth = auth
	resp, err := c.pick().ReEncryptBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	res := resp.GetResults()
	if err := c.verifyBatch(ctx, s, transport.OpReEncryptBatch, req.GetRequestNonce(), auth, reqDigest, resp.GetResponseSignature(),
		len(res), len(items), func(i int) [sha256.Size]byte {
			if e := res[i].GetError(); e != nil {
				return transport.ItemErrorDigest(e.GetCode(), e.GetReason(), e.GetMessage())
			}
			return transport.ItemResultDigest(res[i].GetCiphertext())
		}); err != nil {
		return nil, err
	}
	var keyID []byte
	if toHeader != nil {
		keyID = toHeader.KeyID
	}
	out := make([]BatchResult, len(res))
	for i, r := range res {
		if e := r.GetError(); e != nil {
			if err := itemErrorAlone(s, i, e, r.GetCiphertext()); err != nil {
				return nil, err
			}
			out[i].Err = itemErr(e)
			continue
		}
		if err := c.checkCiphertext(s, r.GetCiphertext(), sizes[i], keyID, len(items[i].ToAssociatedData) > 0); err != nil {
			return nil, err
		}
		out[i].Value = r.GetCiphertext()
	}
	return out, nil
}

// EncryptBatch is Encrypt over items (Data the plaintext, AssociatedData its associated data) in a shared profile:
// one request, one result per item in order. cipheron bounds a batch (batch.maxItems, batch.maxBytes): a batch over
// them is refused whole (package cipheron: ErrInvalidInput with the limits in the error; BatchLimits reads them).
func (c *Client) EncryptBatch(ctx context.Context, profile string, items []BatchItem) (_ []BatchResult, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	s, err := c.batchScope(ctx, profile, items)
	if err != nil {
		return nil, err
	}
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]BatchResult, error) { return c.encryptBatchOnce(ctx, s, items) })
}

// DecryptBatch is Decrypt over items (Data the ciphertext, AssociatedData the associated data it was made with) in
// a shared profile.
func (c *Client) DecryptBatch(ctx context.Context, profile string, items []BatchItem) (_ []BatchResult, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	s, err := c.batchScope(ctx, profile, items)
	if err != nil {
		return nil, err
	}
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]BatchResult, error) { return c.decryptBatchOnce(ctx, s, items) })
}

// ReEncryptBatch is ReEncrypt over items (Data the stored ciphertext, AssociatedData its associated data,
// ToAssociatedData the new one's, equal to AssociatedData: checkReEncryptItems) in a shared profile.
func (c *Client) ReEncryptBatch(ctx context.Context, profile string, items []BatchItem) (_ []BatchResult, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := checkReEncryptItems(items); err != nil {
		return nil, err
	}
	s, err := c.batchScope(ctx, profile, items)
	if err != nil {
		return nil, err
	}
	return retried(ctx, c, s, func(ctx context.Context, s scope) ([]BatchResult, error) {
		return c.reencryptBatchOnce(ctx, s, items, nil, nil)
	})
}

func (c *Client) batchScope(ctx context.Context, profile string, items []BatchItem) (scope, error) {
	if err := c.open(); err != nil {
		return scope{}, err
	}
	if err := checkBatchItems(items); err != nil {
		return scope{}, err
	}
	if err := c.batchFits(profile, items, 0); err != nil {
		return scope{}, err
	}
	k, err := c.sharedKeys(ctx, profile)
	if err != nil {
		return scope{}, err
	}
	return scope{profile: profile, k: k}, nil
}

// tenantBatchScope is the handle's scope for a batch.
func (t *Tenant) batchScope(ctx context.Context, items []BatchItem, extra int) (scope, error) {
	if err := checkBatchItems(items); err != nil {
		return scope{}, err
	}
	if err := t.c.batchFits(t.profile, items, extra); err != nil {
		return scope{}, err
	}
	return t.scope(ctx, 0)
}

// EncryptBatch is Client.EncryptBatch for the tenant.
func (t *Tenant) EncryptBatch(ctx context.Context, items []BatchItem) (_ []BatchResult, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	s, err := t.batchScope(ctx, items, 0)
	if err != nil {
		return nil, err
	}
	return retried(ctx, t.c, s, func(ctx context.Context, s scope) ([]BatchResult, error) { return t.c.encryptBatchOnce(ctx, s, items) })
}

// DecryptBatch is Client.DecryptBatch for the tenant (every item a ciphertext of the handle's blob, in a wrapped
// profile).
func (t *Tenant) DecryptBatch(ctx context.Context, items []BatchItem) (_ []BatchResult, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	s, err := t.batchScope(ctx, items, 0)
	if err != nil {
		return nil, err
	}
	return retried(ctx, t.c, s, func(ctx context.Context, s scope) ([]BatchResult, error) { return t.c.decryptBatchOnce(ctx, s, items) })
}

// ReEncryptBatch is Client.ReEncryptBatch for the tenant: in a wrapped profile every item is moved from the handle's
// blob to the blob to (as Tenant.ReEncrypt); in a derived one to is nil.
func (t *Tenant) ReEncryptBatch(ctx context.Context, items []BatchItem, to []byte) (_ []BatchResult, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	if err := checkReEncryptItems(items); err != nil {
		return nil, err
	}
	s, err := t.batchScope(ctx, items, len(to))
	if err != nil {
		return nil, err
	}
	toHeader, err := t.target(s, to)
	if err != nil {
		return nil, err
	}
	to = bytes.Clone(to)
	return retried(ctx, t.c, s, func(ctx context.Context, s scope) ([]BatchResult, error) {
		return t.c.reencryptBatchOnce(ctx, s, items, to, toHeader)
	})
}

// TenantKeyRef names one tenant key blob: its tenant and the blob.
type TenantKeyRef struct {
	Tenant string
	Blob   []byte
}

// TenantKeyResult is one item of RewrapTenantKeyBatch: the rewrapped key, or the item's own failure.
type TenantKeyResult struct {
	Key *TenantKey
	Err error
}

// RewrapTenantKeyBatch is RewrapTenantKey over a list of (tenant, blob) of a wrapped profile — a sweep across
// tenants. Every blob is checked before anything is sent (as RewrapTenantKey checks it); each answer is checked as
// RewrapTenantKey's is (the same key id, signing key, creation time and fingerprint). Like RewrapTenantKey it is
// never sent again automatically: each call is a new blob per item.
func (c *Client) RewrapTenantKeyBatch(ctx context.Context, profile string, keys []TenantKeyRef) (_ []TenantKeyResult, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	if len(keys) == 0 || len(keys) > transport.MaxBatchItems {
		return nil, fmt.Errorf("cipheron: a batch holds 1 to %d items, not %d", transport.MaxBatchItems, len(keys))
	}
	olds := make([]*transport.TenantKeyHeader, len(keys))
	n := 0
	for i, r := range keys {
		h, err := c.checkBlob(profile, r.Tenant, r.Blob)
		if err != nil {
			return nil, err
		}
		olds[i] = h
		n += 2*len(r.Blob) + len(r.Tenant) + 64
	}
	if err := c.fits(profile, n); err != nil {
		return nil, err
	}
	k, err := c.wrappedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	// Sent once: a second execution would make a second set of blobs (WithRetry never sends it again either) — and
	// once more only after cipheron's start barrier refusal, which says nothing ran (afterStart).
	return afterStart(ctx, c, profile, func(ctx context.Context) ([]TenantKeyResult, error) {
		return c.rewrapBatchOnce(ctx, scope{profile: profile, k: k}, keys, olds)
	})
}

func (c *Client) rewrapBatchOnce(ctx context.Context, s scope, keys []TenantKeyRef, olds []*transport.TenantKeyHeader,
) ([]TenantKeyResult, error) {
	req := &cipheronv1.RewrapTenantKeyBatchRequest{Profile: s.profile, RequestNonce: newNonce()}
	digests := make([][sha256.Size]byte, len(keys))
	for i, r := range keys {
		req.Items = append(req.Items, &cipheronv1.RewrapTenantKeyBatchItem{Tenant: r.Tenant, TenantKey: r.Blob})
		digests[i] = transport.RewrapTenantKeyDigest(r.Tenant, r.Blob)
	}
	reqDigest := transport.BatchDigest(digests)
	auth, err := c.auth(s.profile, transport.OpRewrapTenantKeyBatch, req.GetRequestNonce(), reqDigest)
	if err != nil {
		return nil, err
	}
	req.Auth = auth
	resp, err := c.pick().RewrapTenantKeyBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	res := resp.GetResults()
	if err := c.verifyBatch(ctx, s, transport.OpRewrapTenantKeyBatch, req.GetRequestNonce(), auth, reqDigest,
		resp.GetResponseSignature(), len(res), len(keys), func(i int) [sha256.Size]byte {
			if e := res[i].GetError(); e != nil {
				return transport.ItemErrorDigest(e.GetCode(), e.GetReason(), e.GetMessage())
			}
			r := res[i]
			return transport.ItemResultDigest(r.GetTenantKey(), r.GetSigningPublicKey(), []byte(r.GetFingerprint()))
		}); err != nil {
		return nil, err
	}
	out := make([]TenantKeyResult, len(res))
	for i, r := range res {
		if e := r.GetError(); e != nil {
			if err := itemErrorAlone(s, i, e, r.GetTenantKey(), r.GetSigningPublicKey(), []byte(r.GetFingerprint())); err != nil {
				return nil, err
			}
			out[i].Err = itemErr(e)
			continue
		}
		h, err := rewrapAnswer(s.profile, keys[i].Tenant, olds[i], r.GetTenantKey(), r.GetSigningPublicKey(), r.GetFingerprint())
		if err != nil {
			return nil, err
		}
		if err := c.checkWriter(s.profile, h.WrappingVersion, "a tenant key blob"); err != nil {
			return nil, err
		}
		out[i].Key = tenantKeyOf(h, r.GetTenantKey())
	}
	return out, nil
}

// ReEncryptAcrossScope names where a ciphertext is, for ReEncryptAcross: a profile, and in a perTenant profile the
// tenant — with its tenant key blob in a wrapped one (the blob the ciphertext was made under, or the blob to make
// it under).
type ReEncryptAcrossScope struct {
	Profile, Tenant string
	TenantKey       []byte
}

// ReEncryptAcross moves a ciphertext from one profile to another profile the SAME cipheron serves, without the
// plaintext leaving cipheron: it is decrypted in from and encrypted in to with the same associated data
// (WithAssociatedData; WithTargetAssociatedData must be the same: the move keeps the binding), and the answer is
// signed by BOTH profiles' response keys, each checked
// against its profile's identity (pinned or first seen). The caller's entry needs operation export in from and import
// in to (and its tenants; reencrypt is within a profile only and never crosses profiles), and retenant in from when the
// move changes the tenant (another tenant, or between a shared and a perTenant profile); this client's request key
// signs the request for both (an entry with request keys in the
// target must list it). from and to must be different profiles (a move within a profile is ReEncrypt; a ciphertext
// never moves to another tenant of its profile). WithTargetAssociatedData must be WithAssociatedData's (reencryptOpts).
// Import is a write grant into to (transport.OpImport).
// Under WithRetry it is sent again after a transient refusal, as ReEncrypt is, each attempt a fresh request.
func (c *Client) ReEncryptAcross(ctx context.Context, from, to ReEncryptAcrossScope, ciphertext []byte,
	opts ...CallOption,
) (_ []byte, err error) {
	defer func() { err = c.finish(ctx, from.Profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	if from.Profile == to.Profile {
		return nil, fmt.Errorf("%w: ReEncryptAcross moves a ciphertext to ANOTHER profile; within profile %q it is "+
			"ReEncrypt, and never to another tenant", ErrTenancy, from.Profile)
	}
	if err := c.fits(from.Profile, len(ciphertext)+len(from.TenantKey)+len(to.TenantKey)+len(to.Profile)+len(to.Tenant)+
		len(co.aad)+len(co.toAAD)+maxCiphertextOverhead()); err != nil {
		return nil, err
	}
	fs, err := c.acrossScope(ctx, from)
	if err != nil {
		return nil, err
	}
	ts, err := c.acrossScope(ctx, to)
	if err != nil {
		return nil, err
	}
	// Retried as ReEncrypt is (retry.go): a second execution only makes another ciphertext of the target profile, and
	// each attempt is a fresh request — reencryptAcrossOnce draws its nonce and makes both signatures anew. The
	// observer is told the source profile, the call's own.
	return retryCall(ctx, c, fs.profile, func(ctx context.Context) ([]byte, error) {
		return c.reencryptAcrossOnce(ctx, fs, ts, ciphertext, co)
	})
}

// acrossScope is the scope of one side of ReEncryptAcross: the profile's keys and, for a perTenant profile, the
// tenant handle's checks (its blob's header and pin in a wrapped one).
func (c *Client) acrossScope(ctx context.Context, sc ReEncryptAcrossScope) (scope, error) {
	if sc.Tenant == "" && sc.TenantKey == nil {
		k, err := c.sharedKeys(ctx, sc.Profile)
		if err != nil {
			return scope{}, err
		}
		return scope{profile: sc.Profile, k: k}, nil
	}
	return c.Tenant(sc.Profile, sc.Tenant, sc.TenantKey).scope(ctx, 0)
}

func (c *Client) reencryptAcrossOnce(ctx context.Context, fs, ts scope, ciphertext []byte, co callOptions) ([]byte, error) {
	kid, err := parseCiphertext(fs, ciphertext, co.aad)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext) - kid.Overhead()
	ext := transport.ReEncryptExt{AssociatedData: co.aad, ToAssociatedData: co.toAAD, ToProfile: ts.profile, ToTenant: ts.tenant}
	nonce := newNonce()
	reqDigest := transport.ReEncryptDigestExt(ciphertext, fs.tenant, fs.blob, ts.blob, ext)
	auth, err := c.auth(fs.profile, transport.OpReEncrypt, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	toAuth, err := c.auth(ts.profile, transport.OpReEncrypt, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().ReEncrypt(ctx, &cipheronv1.ReEncryptRequest{Profile: fs.profile, Ciphertext: ciphertext,
		Tenant: fs.tenant, TenantKey: fs.blob, ToTenantKey: ts.blob, RequestNonce: nonce, Auth: auth,
		AssociatedData: co.aad, ToAssociatedData: co.toAAD, ToProfile: ts.profile, ToTenant: ts.tenant, ToAuth: toAuth})
	if err != nil {
		return nil, err
	}
	ct := resp.GetCiphertext()
	respDigest := transport.CiphertextResponseDigest(ct)
	if err := c.verifyResponse(ctx, fs.profile, fs.k, transport.OpReEncrypt, nonce, auth, reqDigest, respDigest,
		resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	if err := c.verifyResponse(ctx, ts.profile, ts.k, transport.OpReEncrypt, nonce, auth, reqDigest, respDigest,
		resp.GetToResponseSignature()); err != nil {
		return nil, err
	}
	var keyID []byte
	if ts.h != nil {
		keyID = ts.h.KeyID
	}
	if err := c.checkCiphertext(ts, ct, n, keyID, len(co.toAAD) > 0); err != nil {
		return nil, err
	}
	return ct, nil
}

// BatchLimits reads cipheron's batch limits from a CIPHERON_BATCH_LIMIT refusal: (maxItems, maxBytes, true), or
// false for any other error.
func BatchLimits(err error) (maxItems int, maxBytes int64, ok bool) {
	st, isStatus := status.FromError(err)
	if !isStatus || st.Code() != codes.InvalidArgument {
		return 0, 0, false
	}
	for _, d := range st.Details() {
		if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo && ei.GetDomain() == transport.ErrorDomain &&
			ei.GetReason() == transport.ReasonBatchLimit {
			items, err1 := strconv.Atoi(ei.GetMetadata()["maxItems"])
			n, err2 := strconv.ParseInt(ei.GetMetadata()["maxBytes"], 10, 64)
			if err1 != nil || err2 != nil || items < 1 || n < 1 {
				return 0, 0, false
			}
			return items, n, true
		}
	}
	return 0, 0, false
}
