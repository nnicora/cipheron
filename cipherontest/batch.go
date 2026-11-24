package cipherontest

// batch.go — the fake's batch operations: each item served as the single operation serves it, one auth and one
// response signature for the batch (transport.BatchDigest), an item's failure its ItemError. The fake's batch
// limits are cipheron's (SetBatchMaxItems, SetBatchMaxBytes; the payload counted by transport.BatchBytes), answered
// CIPHERON_BATCH_LIMIT with cipheron's message.

import (
	"context"
	"crypto/sha256"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// DefaultBatchMaxItems and DefaultBatchMaxBytes are the fake's batch limits unless SetBatchMaxItems and
// SetBatchMaxBytes change them: cipheron's defaults (transport's, the one definition).
const (
	DefaultBatchMaxItems = transport.DefaultBatchMaxItems
	DefaultBatchMaxBytes = transport.DefaultBatchMaxBytes
)

// SetBatchMaxItems sets the most items the fake accepts in a batch (0: DefaultBatchMaxItems), at most
// transport.MaxBatchItems, as cipheron's batch.maxItems: the fake never accepts a batch cipheron could not.
func (s *Server) SetBatchMaxItems(n int) {
	if n < 0 || n > transport.MaxBatchItems {
		s.tb.Fatalf("cipherontest: batch.maxItems %d: 0 (the default) to %d, as cipheron's", n, transport.MaxBatchItems)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchMax = n
}

// SetBatchMaxBytes sets the most payload bytes the fake accepts in a batch, counted as cipheron counts them
// (transport.BatchBytes; 0: DefaultBatchMaxBytes), at most transport.MaxBatchMaxBytes, as cipheron's batch.maxBytes.
func (s *Server) SetBatchMaxBytes(n int64) {
	if n < 0 || n > transport.MaxBatchMaxBytes {
		s.tb.Fatalf("cipherontest: batch.maxBytes %d: 0 (the default) to %d, as cipheron's", n, transport.MaxBatchMaxBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchMaxBytes = n
}

// BatchCalls is how many batch requests the fake has served (any operation, any outcome past its limits);
// BatchRefusals how many it refused for its limits (CIPHERON_BATCH_LIMIT).
func (s *Server) BatchCalls() int64    { return s.batchCalls.Load() }
func (s *Server) BatchRefusals() int64 { return s.batchRefusals.Load() }

// batchBytes is what a batch's items and request-level fields count toward batch.maxBytes (transport.BatchBytes).
func batchBytes[T any](items []T, fields func(T) [][]byte, request ...[]byte) int64 {
	n := transport.BatchBytes(request...)
	for _, it := range items {
		n += transport.BatchBytes(fields(it)...)
	}
	return n
}

// checkBatch holds a batch of n items and bytes payload bytes to the limits, after admission and before any key is
// used, as cipheron does — with its messages and its ErrorInfo.
func (s *Server) checkBatch(n int, bytes int64) error {
	s.mu.Lock()
	limit, maxBytes := s.batchMax, s.batchMaxBytes
	s.mu.Unlock()
	if limit == 0 {
		limit = DefaultBatchMaxItems
	}
	if maxBytes == 0 {
		maxBytes = DefaultBatchMaxBytes
	}
	if n == 0 {
		return status.Error(codes.InvalidArgument, transport.EmptyBatchMessage)
	}
	if n > limit || bytes > maxBytes {
		s.batchRefusals.Add(1)
		st, err := status.New(codes.InvalidArgument, transport.BatchLimitMessage(n, bytes, limit, maxBytes)).WithDetails(
			&errdetails.ErrorInfo{Reason: transport.ReasonBatchLimit, Domain: transport.ErrorDomain,
				Metadata: map[string]string{"maxItems": strconv.Itoa(limit), "maxBytes": strconv.FormatInt(maxBytes, 10)}})
		if err != nil {
			panic(err)
		}
		return st.Err()
	}
	s.batchCalls.Add(1)
	return nil
}

// tooManyItems is cipheron's answer to a batch of more than transport.MaxBatchItems items, which it refuses before
// decoding it — before admission, the same to every caller, naming no configured limit: INVALID_ARGUMENT with
// transport.TooManyItemsMessage and no ErrorInfo.
func tooManyItems(n int) error {
	if n > transport.MaxBatchItems {
		return status.Error(codes.InvalidArgument, transport.TooManyItemsMessage)
	}
	return nil
}

// lastDropped is items without its last one when drop is set (ShortBatch: before the response signature is made;
// BatchResultDropped: after), items itself otherwise.
func lastDropped[T any](items []T, drop bool) []T {
	if drop && len(items) > 0 {
		return items[:len(items)-1]
	}
	return items
}

// itemError is err as a batch item's error (its code, its ErrorInfo reason, its message).
func itemError(err error) (*cipheronv1.ItemError, [sha256.Size]byte) {
	st, _ := status.FromError(err)
	reason := ""
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			reason = ei.GetReason()
		}
	}
	e := &cipheronv1.ItemError{Code: uint32(st.Code()), Reason: reason, Message: st.Message()}
	return e, transport.ItemErrorDigest(e.GetCode(), e.GetReason(), e.GetMessage())
}

func (s *Server) EncryptBatch(_ context.Context, r *cipheronv1.EncryptBatchRequest) (*cipheronv1.EncryptBatchResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	if err := tooManyItems(len(r.GetItems())); err != nil {
		return nil, err
	}
	profile, tenant, blob := r.GetProfile(), r.GetTenant(), r.GetTenantKey()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	digests := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		digests[i] = transport.EncryptDigestAAD(it.GetEnc(), it.GetSealedPlaintext(), tenant, blob, it.GetAssociatedData())
	}
	reqDigest := transport.BatchDigest(digests)
	if err := s.admit(profile, transport.OpEncrypt, transport.OpEncryptBatch, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(!k.tenancy.Wrapped()); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, blob)
	if err != nil {
		return nil, err
	}
	if err := s.checkBatch(len(r.GetItems()), batchBytes(r.GetItems(), func(it *cipheronv1.EncryptBatchItem) [][]byte {
		return [][]byte{it.GetEnc(), it.GetSealedPlaintext(), it.GetAssociatedData()}
	}, blob)); err != nil {
		return nil, err
	}
	out := &cipheronv1.EncryptBatchResponse{}
	rd := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		if len(it.GetAssociatedData()) > transport.MaxAssociatedDataLen {
			e, d := itemError(errAssociatedData())
			out.Results, rd[i] = append(out.Results, &cipheronv1.EncryptBatchResult{Error: e}), d
			continue
		}
		pt, err := transport.OpenRequestPayload(s.formats, k.hpke, profile, transport.OpEncrypt, tenant, key, it.GetEnc(),
			it.GetSealedPlaintext())
		if err != nil {
			e, d := itemError(status.Error(codes.InvalidArgument, "the sealed plaintext could not be opened"))
			out.Results, rd[i] = append(out.Results, &cipheronv1.EncryptBatchResult{Error: e}), d
			continue
		}
		if err := s.sealAAD(it.GetAssociatedData()); err != nil {
			e, d := itemError(err)
			out.Results, rd[i] = append(out.Results, &cipheronv1.EncryptBatchResult{Error: e}), d
			continue
		}
		ct := s.seal(k, m, profile, tenant, tk, pt, it.GetAssociatedData())
		out.Results, rd[i] = append(out.Results, &cipheronv1.EncryptBatchResult{Ciphertext: ct}), transport.ItemResultDigest(ct)
	}
	out.Results, rd = lastDropped(out.GetResults(), m == ShortBatch), lastDropped(rd, m == ShortBatch)
	out.ResponseSignature = s.respSig(k, m, profile, transport.OpEncryptBatch, r.GetRequestNonce(), r.GetAuth(), reqDigest,
		transport.BatchDigest(rd))
	out.Results = lastDropped(out.GetResults(), m == BatchResultDropped)
	return out, nil
}

func (s *Server) DecryptBatch(_ context.Context, r *cipheronv1.DecryptBatchRequest) (*cipheronv1.DecryptBatchResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	if err := tooManyItems(len(r.GetItems())); err != nil {
		return nil, err
	}
	profile, tenant, blob, rpk := r.GetProfile(), r.GetTenant(), r.GetTenantKey(), r.GetRecipientPublicKey()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	digests := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		digests[i] = transport.DecryptDigestAAD(rpk, it.GetCiphertext(), tenant, blob, it.GetAssociatedData())
	}
	reqDigest := transport.BatchDigest(digests)
	if err := s.admit(profile, transport.OpDecrypt, transport.OpDecryptBatch, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(false); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, blob)
	if err != nil {
		return nil, err
	}
	if err := s.checkBatch(len(r.GetItems()), batchBytes(r.GetItems(), func(it *cipheronv1.DecryptBatchItem) [][]byte {
		return [][]byte{it.GetCiphertext(), it.GetAssociatedData()}
	}, blob, rpk)); err != nil {
		return nil, err
	}
	pk, err := transport.ParsePublicKey(rpk)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "recipient_public_key")
	}
	info := transport.ResponseInfoTenant(s.formats, profile, transport.OpDecrypt, tenant)
	out := &cipheronv1.DecryptBatchResponse{}
	rd := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		pt, err := s.open(k, profile, tenant, tk, it.GetCiphertext(), it.GetAssociatedData())
		if err != nil {
			e, d := itemError(err)
			out.Results, rd[i] = append(out.Results, &cipheronv1.DecryptBatchResult{Error: e}), d
			continue
		}
		enc, sealed, err := transport.Seal(pk, info, pt)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		if m == GarbledPlaintext {
			sealed[0] ^= 1
		}
		out.Results = append(out.Results, &cipheronv1.DecryptBatchResult{Enc: enc, SealedPlaintext: sealed})
		rd[i] = transport.ItemResultDigest(rpk, enc, sealed)
	}
	out.Results, rd = lastDropped(out.GetResults(), m == ShortBatch), lastDropped(rd, m == ShortBatch)
	out.ResponseSignature = s.respSig(k, m, profile, transport.OpDecryptBatch, r.GetRequestNonce(), r.GetAuth(), reqDigest,
		transport.BatchDigest(rd))
	out.Results = lastDropped(out.GetResults(), m == BatchResultDropped)
	return out, nil
}

func (s *Server) ReEncryptBatch(_ context.Context, r *cipheronv1.ReEncryptBatchRequest) (*cipheronv1.ReEncryptBatchResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	if err := tooManyItems(len(r.GetItems())); err != nil {
		return nil, err
	}
	profile, tenant, blob, to := r.GetProfile(), r.GetTenant(), r.GetTenantKey(), r.GetToTenantKey()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	digests := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		digests[i] = transport.ReEncryptDigestExt(it.GetCiphertext(), tenant, blob, to, transport.ReEncryptExt{
			AssociatedData: it.GetAssociatedData(), ToAssociatedData: it.GetToAssociatedData()})
	}
	reqDigest := transport.BatchDigest(digests)
	if err := s.admit(profile, transport.OpReEncrypt, transport.OpReEncryptBatch, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(!k.tenancy.Wrapped()); err != nil {
		return nil, err
	}
	tk, err := s.tenantOf(k, profile, tenant, blob)
	if err != nil {
		return nil, err
	}
	var toKeys *tenantKeys
	if tk != nil {
		if toKeys, err = s.tenantOf(k, profile, tenant, to); err != nil {
			return nil, err
		}
	}
	if err := s.checkBatch(len(r.GetItems()), batchBytes(r.GetItems(), func(it *cipheronv1.ReEncryptBatchItem) [][]byte {
		return [][]byte{it.GetCiphertext(), it.GetAssociatedData(), it.GetToAssociatedData()}
	}, blob, to)); err != nil {
		return nil, err
	}
	out := &cipheronv1.ReEncryptBatchResponse{}
	rd := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		var pt []byte
		// The item's associated data first, before it is opened (as cipheron): its shape, then a re-binding decided with
		// the grants (decrypt and encrypt in the profile); a refusal is this item's error.
		err := reencryptAAD(it.GetAssociatedData(), it.GetToAssociatedData())
		if err == nil && rebinds(it.GetAssociatedData(), it.GetToAssociatedData()) {
			err = s.grantedRebind(profile, profile)
		}
		if err == nil {
			pt, err = s.open(k, profile, tenant, tk, it.GetCiphertext(), it.GetAssociatedData())
		}
		if err == nil {
			err = s.sealAAD(it.GetToAssociatedData())
		}
		if err != nil {
			e, d := itemError(err)
			out.Results, rd[i] = append(out.Results, &cipheronv1.ReEncryptBatchResult{Error: e}), d
			continue
		}
		ct := s.seal(k, m, profile, tenant, toKeys, pt, it.GetToAssociatedData())
		out.Results, rd[i] = append(out.Results, &cipheronv1.ReEncryptBatchResult{Ciphertext: ct}), transport.ItemResultDigest(ct)
	}
	out.Results, rd = lastDropped(out.GetResults(), m == ShortBatch), lastDropped(rd, m == ShortBatch)
	out.ResponseSignature = s.respSig(k, m, profile, transport.OpReEncryptBatch, r.GetRequestNonce(), r.GetAuth(), reqDigest,
		transport.BatchDigest(rd))
	out.Results = lastDropped(out.GetResults(), m == BatchResultDropped)
	return out, nil
}

func (s *Server) RewrapTenantKeyBatch(ctx context.Context, r *cipheronv1.RewrapTenantKeyBatchRequest) (*cipheronv1.RewrapTenantKeyBatchResponse, error) {
	if err := s.early(); err != nil {
		return nil, err
	}
	if err := tooManyItems(len(r.GetItems())); err != nil {
		return nil, err
	}
	profile := r.GetProfile()
	k, m, key, err := s.state(profile)
	if err != nil {
		return nil, err
	}
	digests := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		digests[i] = transport.RewrapTenantKeyDigest(it.GetTenant(), it.GetTenantKey())
	}
	reqDigest := transport.BatchDigest(digests)
	if err := s.admit(profile, transport.OpProvision, transport.OpRewrapTenantKeyBatch, r.GetRequestNonce(), r.GetAuth(), key, reqDigest); err != nil {
		return nil, err
	}
	if err := s.late(true); err != nil {
		return nil, err
	}
	if !k.tenancy.Wrapped() {
		return nil, errNotWrapped
	}
	if err := s.checkBatch(len(r.GetItems()), batchBytes(r.GetItems(), func(it *cipheronv1.RewrapTenantKeyBatchItem) [][]byte {
		return [][]byte{[]byte(it.GetTenant()), it.GetTenantKey()}
	})); err != nil {
		return nil, err
	}
	out := &cipheronv1.RewrapTenantKeyBatchResponse{}
	rd := make([][sha256.Size]byte, len(r.GetItems()))
	for i, it := range r.GetItems() {
		nb, pub, fp, err := s.rewrap(k, m, profile, it.GetTenant(), it.GetTenantKey())
		if err != nil {
			e, d := itemError(err)
			out.Results, rd[i] = append(out.Results, &cipheronv1.RewrapTenantKeyBatchResult{Error: e}), d
			continue
		}
		out.Results = append(out.Results, &cipheronv1.RewrapTenantKeyBatchResult{TenantKey: nb, SigningPublicKey: pub, Fingerprint: fp})
		rd[i] = transport.ItemResultDigest(nb, pub, []byte(fp))
	}
	out.Results, rd = lastDropped(out.GetResults(), m == ShortBatch), lastDropped(rd, m == ShortBatch)
	out.ResponseSignature = s.respSig(k, m, profile, transport.OpRewrapTenantKeyBatch, r.GetRequestNonce(), r.GetAuth(),
		reqDigest, transport.BatchDigest(rd))
	out.Results = lastDropped(out.GetResults(), m == BatchResultDropped)
	return out, nil
}
