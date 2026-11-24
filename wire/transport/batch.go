package transport

// batch.go — the digests of the batch operations (EncryptBatch, DecryptBatch, ReEncryptBatch, RewrapTenantKeyBatch).
// A batch is signed once each way, over the request transcript and the response transcript of its own transcript
// label (OpEncryptBatch, …), whose digests are these: a list of the single operation's digests, one per item, in
// order. An item cannot be dropped, added, moved or replaced without changing the digest, and no batch digest is a
// single operation's (its label differs, and so does its form).

import (
	"crypto/sha256"
	"encoding/binary"
)

// MaxBatchItems is the most items a batch may hold whatever the configuration (cipheron's batch.maxItems is at most
// this): it bounds an unverified list. cipheron counts a batch request's items before it decodes it, on both
// protocols, and refuses one of more (TooManyItemsMessage); a client counts an answer's results before it hashes
// them.
const MaxBatchItems = 4096

// The first byte of an item's result digest: a result, or an item error.
const (
	itemOK    byte = 0
	itemError byte = 1
)

// BatchDigest is a batch's request digest — or, over the results' digests, its response digest:
//
//	Digest( count (4 bytes, big-endian), digest of item 0, digest of item 1, … )
//
// each item digest being the single operation's request digest of the item's fields (EncryptDigestAAD,
// DecryptDigestAAD, ReEncryptDigestExt, RewrapTenantKeyDigest) — with the batch's own scope (tenant, blobs,
// recipient key) in each — or, for the answer, ItemResultDigest or ItemErrorDigest.
func BatchDigest(items [][sha256.Size]byte) [sha256.Size]byte {
	fields := make([][]byte, 0, len(items)+1)
	fields = append(fields, binary.BigEndian.AppendUint32(nil, uint32(len(items))))
	for i := range items {
		fields = append(fields, items[i][:])
	}
	return Digest(fields...)
}

// ItemResultDigest is a batch item's result digest: Digest(0x00, the single answer's response fields…) — for
// EncryptBatch and ReEncryptBatch the ciphertext; for DecryptBatch the recipient key, enc and sealed plaintext; for
// RewrapTenantKeyBatch the blob, its signing public key and its fingerprint.
func ItemResultDigest(fields ...[]byte) [sha256.Size]byte {
	return Digest(append([][]byte{{itemOK}}, fields...)...)
}

// ItemErrorDigest is a batch item's error digest: Digest(0x01, code (4 bytes, big-endian), reason, message). The
// first byte differs from a result's, so an error never reads as a result.
func ItemErrorDigest(code uint32, reason, message string) [sha256.Size]byte {
	return Digest([]byte{itemError}, binary.BigEndian.AppendUint32(nil, code), []byte(reason), []byte(message))
}

// The batch limits' defaults and bounds — the ONE definition cipheron's configuration (batch.maxItems,
// batch.maxBytes), the sidecar chart's schema, the documentation, the client's batch splitter and the test server
// (cipherontest) use. DefaultBatchMaxBytes is SegmentRequestBytes, cipheron's default listener maxRequestBytes too, so
// a batch the default listener admits fits and a segment of every size a client may choose is served by default;
// MaxBatchMaxBytes is the largest (64 MiB).
const (
	DefaultBatchMaxItems = 128
	DefaultBatchMaxBytes = SegmentRequestBytes
	MaxBatchMaxBytes     = 64 << 20
)

// SealOverhead is what the HPKE seal of a request payload adds to it (the AES-256-GCM tag); a sealed payload also
// travels with its encapsulated key (EncLen bytes, a field of its own).
const SealOverhead = 16

// The size of the largest request a segmented object's segment travels in: one segment of MaxSegmentSize bytes, alone
// in a batch.
const (
	// MaxBatchFixedBytes is what a batch request counts toward batch.maxBytes (BatchBytes) besides its items, at most:
	// the request's tenant key blobs (two: ReEncryptBatch's tenant_key and to_tenant_key) and DecryptBatch's
	// recipient key.
	MaxBatchFixedBytes = 2*MaxTenantKeyLen + EncLen
	// MaxSegmentItemBytes is what one segment of MaxSegmentSize bytes counts toward batch.maxBytes as an item, at
	// most: as an EncryptBatch item, SealedItemBytes(MaxSegmentSize, MaxAssociatedDataLen) — the encapsulated key,
	// the segment, the seal's tag and its associated data; as a DecryptBatch item its ciphertext (the segment and at
	// most MaxSegmentOverhead) and its associated data; as a ReEncryptBatch item that ciphertext and both associated
	// data. The largest of the three.
	MaxSegmentItemBytes = max(EncLen+MaxSegmentSize+SealOverhead+MaxAssociatedDataLen,
		MaxSegmentSize+MaxSegmentOverhead+MaxAssociatedDataLen,
		MaxSegmentSize+MaxSegmentOverhead+2*MaxAssociatedDataLen)
	// MaxBatchFraming bounds what a batch request of one item holds beyond its payload fields: its profile, tenant,
	// nonce and auth, and every field's protobuf tag and length.
	MaxBatchFraming = 4 << 10
	// SegmentRequestBytes is the largest request message one segment of MaxSegmentSize bytes travels in, the batch's
	// payload and its framing: MaxBatchFixedBytes + MaxSegmentItemBytes + MaxBatchFraming — 16 918 211 bytes, 16 MiB
	// and 140 995.
	SegmentRequestBytes = int64(MaxBatchFixedBytes + MaxSegmentItemBytes + MaxBatchFraming)
)

// BatchBytes is what a batch counts toward batch.maxBytes: the sum of the lengths of its payload fields — the
// request's tenant key blobs (tenant_key, to_tenant_key) and DecryptBatch's recipient_public_key, and per item its
// payload: EncryptBatch enc + sealed_plaintext + associated_data; DecryptBatch ciphertext + associated_data;
// ReEncryptBatch ciphertext + associated_data + to_associated_data; RewrapTenantKeyBatch tenant + tenant_key. The
// field names, the tags and the nonces and the auth are not counted (the listener's
// maxRequestBytes bounds the whole message).
func BatchBytes(fields ...[]byte) int64 {
	var n int64
	for _, f := range fields {
		n += int64(len(f))
	}
	return n
}

// SealedItemBytes is what an EncryptBatch item of plaintextLen bytes with aadLen bytes of associated data counts
// toward batch.maxBytes once sealed (BatchBytes: its enc, its sealed plaintext, its associated data) — the
// estimate a client splits its batches by before it seals anything.
func SealedItemBytes(plaintextLen, aadLen int) int64 {
	return int64(EncLen) + int64(plaintextLen) + SealOverhead + int64(aadLen)
}
