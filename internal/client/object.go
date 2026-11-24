package client

// object.go — objects larger than one request: the segmented object format (transport/segment.go), each segment
// a ciphertext made with associated data that names the object, its index and whether it is the last, sent through
// the batch operations.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/internal/zeroize"
	"github.com/nnicora/cipheron/wire/transport"
)

// WithSegmentSize is EncryptObject's segment size: the plaintext bytes of each segment (transport.MinSegmentSize to
// transport.MaxSegmentSize; default transport.DefaultSegmentSize). DecryptObject reads it from the object.
func WithSegmentSize(n int) CallOption {
	return func(o *callOptions) { o.segment = n }
}

// objectBatchBytes is the payload (transport.BatchBytes, what cipheron's batch.maxBytes counts) a batch of segments
// carries at most when its segments are smaller: 768 KiB, leaving room in a 1 MiB request for the request's own
// fields and the answer's growth. Small batches keep each request's reservation against cipheron's memory budget
// small, so many are served at once, and fit a listener configured with a maxRequestBytes as low as 1 MiB. A segment
// larger than this travels alone in its batch (inBatches).
const objectBatchBytes = 768 << 10

// objectBatchItems is the most segments in one batch (cipheron's default batch.maxItems).
const objectBatchItems = transport.DefaultBatchMaxItems

// batchFixedBytes is what a batch request counts toward batch.maxBytes besides its items, at most
// (transport.MaxBatchFixedBytes).
const batchFixedBytes = transport.MaxBatchFixedBytes

// itemBytes is what item counts toward batch.maxBytes (transport.BatchBytes) in a batch that seals its items
// (EncryptBatch: transport.SealedItemBytes, the encapsulated key and the seal's tag included) or not (DecryptBatch:
// the ciphertext and the associated data; ReEncryptBatch: and the new ciphertext's associated data).
func itemBytes(item BatchItem, sealed bool) int64 {
	if sealed {
		return transport.SealedItemBytes(len(item.Data), len(item.AssociatedData))
	}
	return transport.BatchBytes(item.Data, item.AssociatedData, item.ToAssociatedData)
}

// checkSegmentFits refuses, before anything is sent, a segment size whose request cannot fit this client's own
// messages (WithMaxMessageBytes): a segment travels in one request, sealed, with its associated data.
func (c *Client) checkSegmentFits(size, aadLen int) error {
	limit := int64(c.maxMessage-wireOverhead) * 3 / 4
	need := int64(batchFixedBytes) + transport.SealedItemBytes(size, aadLen+transport.SegmentAssociatedDataOverhead)
	if need > limit {
		return fmt.Errorf("%w: a segment of %d bytes needs a request of %d bytes, and this client's messages carry at "+
			"most %d (lower WithSegmentSize, or raise WithMaxMessageBytes)", ErrTooLarge, size, need, limit)
	}
	return nil
}

// segmentRefused makes cipheron's refusal of a segment's request as too large (ErrTooLarge: its maxRequestBytes or
// batch.maxBytes) say what to do: an encryption chooses its segment size (chosen: lower WithSegmentSize, or raise
// cipheron's limits); an existing object's segments are its own (raise cipheron's limits). Any other err is returned
// as it is.
func segmentRefused(err error, size int, chosen bool) error {
	if err == nil {
		return nil
	}
	var msg string
	if s, ok := status.FromError(err); ok && s.Code() == codes.ResourceExhausted && SizeRefusal(s) {
		msg = s.Message() // gRPC's own refusal of a request over cipheron's limit
	} else if errors.Is(err, ErrTooLarge) {
		msg = strings.TrimPrefix(err.Error(), ErrTooLarge.Error()+": ")
	} else {
		return err
	}
	if chosen {
		return &tooLargeError{msg: fmt.Sprintf("%s (each segment of %d bytes travels in one request: lower "+
			"WithSegmentSize, or raise cipheron's maxRequestBytes and batch.maxBytes)", msg, size)}
	}
	return &tooLargeError{msg: fmt.Sprintf("%s (the object's segments are %d bytes and each travels in one request: "+
		"raise cipheron's maxRequestBytes and batch.maxBytes)", msg, size)}
}

// SizeRefusal reports whether s is gRPC's own refusal of a message over a size limit: RESOURCE_EXHAUSTED with no
// details and gRPC's wording — not cipheron's busy answer (which carries a reason and a RetryInfo), nor a proxy
// shedding load.
func SizeRefusal(s *status.Status) bool {
	if len(s.Proto().GetDetails()) != 0 {
		return false
	}
	m := s.Message()
	return strings.Contains(m, "larger than max") || strings.Contains(m, "message too large")
}

// checkObjectAAD refuses an object's associated data over transport.MaxObjectAssociatedDataLen, before anything is
// sent: each segment's associated data adds transport.SegmentAssociatedDataOverhead to it, and cipheron would
// refuse every segment.
func checkObjectAAD(co callOptions) error {
	if len(co.aad) > transport.MaxObjectAssociatedDataLen {
		return fmt.Errorf("%w: an object's associated data is at most %d bytes (each segment's associated data adds %d "+
			"bytes to it, and associated data is at most %d)", ErrAssociatedData, transport.MaxObjectAssociatedDataLen,
			transport.SegmentAssociatedDataOverhead, transport.MaxAssociatedDataLen)
	}
	return nil
}

type batchFunc func(ctx context.Context, items []BatchItem) ([]BatchResult, error)

// inBatches sends items through call in batches of at most objectBatchItems items and objectBatchBytes bytes —
// counted as cipheron counts batch.maxBytes (transport.BatchBytes: itemBytes per item, sealed for an EncryptBatch,
// and batchFixedBytes for the request's own payload fields), and within this client's message size — smaller after a
// CIPHERON_BATCH_LIMIT refusal, whose limits it adopts (the refused batch was not served: cipheron checks the limits
// before any key is used), and returns every result in order. The first item error fails the whole call: a segment
// that does not encrypt or decrypt fails its object.
//
// Up to pipelineDepth batches are in flight at once (pipelined): their answers are taken in order, so the outcome is
// the sequential one — after a refusal of the limits, the batches sent behind the refused one are dropped and
// everything from it is sent again in smaller batches. A decryption's plaintexts that are not returned (an error,
// a batch dropped) are wiped.
//
// An item error is returned as a *segmentError (its index and the item's status).
func (c *Client) inBatches(ctx context.Context, items []BatchItem, sealed bool, call batchFunc) ([][]byte, error) {
	maxItems, maxBytes := objectBatchItems, min(int64(objectBatchBytes), int64(c.maxMessage-wireOverhead)*3/4)
	out := make([][]byte, 0, len(items))
	wipe := func(res []BatchResult) {
		if !sealed { // plaintexts: wiped; ciphertexts are not secret, and an encryption's items are the caller's
			for _, r := range res {
				zeroize.Bytes(r.Value)
			}
		}
	}
	type batch struct {
		i, j int
		size int64
		res  []BatchResult
	}
	pos := 0
	err := pipelined(ctx, func() (func(context.Context) (batch, error), error) {
		if pos >= len(items) {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		i, j, size := pos, pos, int64(batchFixedBytes)
		for j < len(items) && j-i < maxItems && (j == i || size+itemBytes(items[j], sealed) <= maxBytes) {
			size += itemBytes(items[j], sealed)
			j++
		}
		pos = j
		return func(ctx context.Context) (batch, error) {
			res, err := call(ctx, items[i:j])
			return batch{i: i, j: j, size: size, res: res}, err
		}, nil
	}, func(b batch, err error) error {
		if n, lim, ok := BatchLimits(err); ok && (b.j-b.i > n || b.size > lim*3/4) && b.j-b.i > 1 {
			maxItems, maxBytes = n, min(lim*3/4, maxBytes)
			pos = b.i
			return errRestart // the same items again, in smaller batches
		}
		if err != nil {
			wipe(b.res)
			return err
		}
		for k, r := range b.res {
			if r.Err != nil {
				wipe(b.res)
				return &segmentError{index: b.i + k, err: r.Err}
			}
		}
		for _, r := range b.res {
			out = append(out, r.Value)
		}
		return nil
	}, func(b batch) { wipe(b.res) })
	if err != nil {
		if !sealed {
			for _, p := range out {
				zeroize.Bytes(p)
			}
		}
		return nil, err
	}
	return out, nil
}

// segmentError is one segment's item error.
type segmentError struct {
	index int
	err   error
}

func (e *segmentError) Error() string { return fmt.Sprintf("segment %d: %v", e.index, e.err) }
func (e *segmentError) Unwrap() error { return e.err }

// integrityFailure reports an item error that says the segment does not decrypt as its position's: INVALID_ARGUMENT
// without the key-version reason (a key version not listed is not the object's fault: it reads again once listed).
func integrityFailure(err error) bool {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		return false
	}
	for _, d := range st.Details() {
		if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo && ei.GetReason() == transport.ReasonKeyVersionUnavailable {
			return false
		}
	}
	return true
}

// encryptObject cuts plaintext into segments of co's size and encrypts them through call.
func (c *Client) encryptObject(ctx context.Context, plaintext []byte, co callOptions, call batchFunc) ([]byte, error) {
	if err := checkObjectAAD(co); err != nil {
		return nil, err
	}
	size := co.segment
	if size == 0 {
		size = transport.DefaultSegmentSize
	}
	if size < transport.MinSegmentSize || size > transport.MaxSegmentSize {
		return nil, fmt.Errorf("cipheron: a segment size is %d to %d bytes, not %d", transport.MinSegmentSize,
			transport.MaxSegmentSize, size)
	}
	if err := c.checkSegmentFits(size, len(co.aad)); err != nil {
		return nil, err
	}
	count := max(1, (len(plaintext)+size-1)/size)
	if count > transport.MaxSegments {
		return nil, fmt.Errorf("%w: %d segments of %d bytes; an object has at most %d (WithSegmentSize)", ErrTooLarge,
			count, size, transport.MaxSegments)
	}
	id := make([]byte, transport.ObjectIDLen)
	_, _ = rand.Read(id) // crypto/rand.Read never fails; it crashes the program instead
	items := make([]BatchItem, count)
	for i := range items {
		lo, hi := i*size, min((i+1)*size, len(plaintext))
		items[i] = BatchItem{Data: plaintext[lo:hi], AssociatedData: transport.SegmentAssociatedData(id, uint32(i),
			i == count-1, co.aad)}
	}
	segs, err := c.inBatches(ctx, items, true, call)
	if err != nil {
		return nil, segmentRefused(err, size, true)
	}
	return transport.MarshalSegmented(transport.Release(), transport.SegmentedHeader{ObjectID: id, SegmentSize: uint32(size),
		Count: uint32(count)}, segs)
}

// decryptObject decrypts a segmented object's segments through call, each with the associated data of its own
// position — so a segment moved, dropped, added or taken from another object does not decrypt — and checks the
// sizes the header names.
func (c *Client) decryptObject(ctx context.Context, object []byte, co callOptions, call batchFunc) ([]byte, error) {
	if err := checkObjectAAD(co); err != nil {
		return nil, err
	}
	h, segs, err := transport.ParseSegmented(transport.Release(), object)
	if err != nil {
		return nil, err
	}
	items := make([]BatchItem, len(segs))
	for i, s := range segs {
		items[i] = BatchItem{Data: s, AssociatedData: transport.SegmentAssociatedData(h.ObjectID, uint32(i),
			i == len(segs)-1, co.aad)}
	}
	pts, err := c.inBatches(ctx, items, false, call)
	err = segmentRefused(err, int(h.SegmentSize), false)
	var f *segmentError
	if errors.As(err, &f) && integrityFailure(f.err) {
		return nil, fmt.Errorf("%w: %w", transport.ErrSegmented, err)
	}
	if err != nil {
		return nil, err
	}
	n := 0
	defer func() {
		if n < 0 { // refused: the segments' plaintexts are not returned
			for _, p := range pts {
				zeroize.Bytes(p)
			}
		}
	}()
	for i, p := range pts {
		last := i == len(pts)-1
		if (!last && len(p) != int(h.SegmentSize)) || len(p) > int(h.SegmentSize) || (last && len(p) == 0 && len(pts) > 1) {
			n = -1
			return nil, fmt.Errorf("%w: segment %d holds %d bytes, and the object's segments hold %d", transport.ErrSegmented,
				i, len(p), h.SegmentSize)
		}
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range pts {
		out = append(out, p...)
		zeroize.Bytes(p) // the segment's own copy: the object's plaintext is out
	}
	return out, nil
}

// checkReEncryptAAD refuses, before anything is sent, an object's associated data of either side of a re-encryption
// (WithAssociatedData, WithTargetAssociatedData) over transport.MaxObjectAssociatedDataLen, as checkObjectAAD does.
func checkReEncryptAAD(co callOptions) error {
	if err := checkObjectAAD(co); err != nil {
		return err
	}
	return checkObjectAAD(callOptions{aad: co.toAAD})
}

// checkKeptSegmentSize refuses a WithSegmentSize other than the object's own (its header h): a re-encrypted segment
// holds the plaintext it held, so the new object keeps the segment size (INVALID_ARGUMENT: package cipheron's
// ErrInvalidInput). Nothing is sent.
func checkKeptSegmentSize(co callOptions, h transport.SegmentedHeader) error {
	if co.segment != 0 && co.segment != int(h.SegmentSize) {
		return status.Errorf(codes.InvalidArgument, "cipheron: a re-encrypted object keeps its segment size, %d bytes; "+
			"WithSegmentSize asks for %d", h.SegmentSize, co.segment)
	}
	return nil
}

// segmentFits refuses segment index of an object whose header is h, before it is sent, when its ciphertext does not
// hold what the header says a segment of its place holds — what DecryptObject refuses once the segment decrypted:
// every segment but the last exactly h.SegmentSize bytes of plaintext, the last at most that and, in an object of
// more than one segment, at least one. Bytes that are not a ciphertext pass here: the batch refuses them before
// anything is sent (parseCiphertext), as DecryptObject's does.
func segmentFits(h transport.SegmentedHeader, index uint32, segment []byte) error {
	kid, err := transport.ParseKeyID(transport.Release(), segment)
	if err != nil {
		return nil
	}
	n := len(segment) - kid.Overhead() // ParseKeyID holds the ciphertext to its header, nonce and tag
	last := index == h.Count-1
	if (!last && n != int(h.SegmentSize)) || n > int(h.SegmentSize) || (last && n == 0 && h.Count > 1) {
		return fmt.Errorf("%w: segment %d holds %d bytes, and the object's segments hold %d", transport.ErrSegmented,
			index, n, h.SegmentSize)
	}
	return nil
}

// reencryptItem is segment index of an object whose header is h as a ReEncryptBatch item: decrypted with the
// associated data of its own position in that object (and co's), made again with the same associated data — the
// same object id and position, and co's target associated data, which reencryptOpts held to co's: a re-encryption
// keeps the binding.
func reencryptItem(h transport.SegmentedHeader, index uint32, segment []byte, co callOptions) BatchItem {
	last := index == h.Count-1
	return BatchItem{Data: segment, AssociatedData: transport.SegmentAssociatedData(h.ObjectID, index, last, co.aad),
		ToAssociatedData: transport.SegmentAssociatedData(h.ObjectID, index, last, co.toAAD)}
}

// reencryptObject re-encrypts a segmented object's segments through call (ReEncryptBatch) into the object again — the
// same object id, segment size and count — each segment decrypted inside cipheron as its own position's (so a segment
// moved, dropped, added or taken from another object does not re-encrypt) and made again as the same position's of the
// same object. No plaintext reaches this client.
func (c *Client) reencryptObject(ctx context.Context, object []byte, co callOptions, call batchFunc) ([]byte, error) {
	if err := checkReEncryptAAD(co); err != nil {
		return nil, err
	}
	h, segs, err := transport.ParseSegmented(transport.Release(), object)
	if err != nil {
		return nil, err
	}
	if err := checkKeptSegmentSize(co, h); err != nil {
		return nil, err
	}
	items := make([]BatchItem, len(segs))
	for i, s := range segs {
		if err := segmentFits(h, uint32(i), s); err != nil {
			return nil, err
		}
		items[i] = reencryptItem(h, uint32(i), s, co)
	}
	cts, err := c.inBatches(ctx, items, false, call)
	err = segmentRefused(err, int(h.SegmentSize), false)
	var f *segmentError
	if errors.As(err, &f) && integrityFailure(f.err) {
		return nil, fmt.Errorf("%w: %w", transport.ErrSegmented, err)
	}
	if err != nil {
		return nil, err
	}
	return transport.MarshalSegmented(transport.Release(), transport.SegmentedHeader{ObjectID: h.ObjectID, SegmentSize: h.SegmentSize, Count: h.Count}, cts)
}

// EncryptObject encrypts an object of any size (up to transport.MaxSegments segments) in a shared profile as a
// segmented object (transport/segment.go): cut into segments (WithSegmentSize), each encrypted by cipheron with
// associated data naming the object (a random id), the segment's index and whether it is the last — and
// WithAssociatedData's, when given — through EncryptBatch. Store the result whole; DecryptObject reads it back and
// detects any segment reordered, dropped, added or taken from another object.
func (c *Client) EncryptObject(ctx context.Context, profile string, plaintext []byte, opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.encryptObject(ctx, plaintext, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.EncryptBatch(ctx, profile, items)
	})
}

// DecryptObject decrypts a segmented object of a shared profile (EncryptObject), with the associated data it was
// made with (WithAssociatedData). A segment that does not decrypt as its own position's — the object truncated,
// reordered, extended or spliced, or other associated data — fails the whole object (transport.ErrSegmented in the
// chain).
func (c *Client) DecryptObject(ctx context.Context, profile string, object []byte, opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.decryptObject(ctx, object, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.DecryptBatch(ctx, profile, items)
	})
}

// EncryptObject is Client.EncryptObject for the tenant.
func (t *Tenant) EncryptObject(ctx context.Context, plaintext []byte, opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.encryptObject(ctx, plaintext, co, t.EncryptBatch)
}

// DecryptObject is Client.DecryptObject for the tenant.
func (t *Tenant) DecryptObject(ctx context.Context, object []byte, opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.decryptObject(ctx, object, co, t.DecryptBatch)
}

// ReEncryptObject has cipheron re-encrypt a segmented object of a shared profile (EncryptObject's or EncryptStream's)
// under the profile's current keys, segment by segment through ReEncryptBatch, and returns the object again: the same
// object id, segment size and segment count, each segment made again as its own position's, so it keeps its binding.
// The plaintext never leaves cipheron — the caller's entry needs the reencrypt operation only, and nothing returned or
// kept here is a plaintext — which is what a migration sweep needs before a master key version is retired.
//
// WithAssociatedData is the stored object's associated data, and WithTargetAssociatedData must be the same (as
// ReEncrypt: reencryptOpts): a re-encryption keeps the binding; anything else is refused before anything is sent.
// WithSegmentSize, when given, must be the
// object's own. The object is checked as DecryptObject checks it: a segment that does not decrypt as its own
// position's — the object truncated, reordered, extended or spliced, or other associated data — fails the whole object
// (transport.ErrSegmented in the chain), and so does a segment whose size is not the one its place holds. Nothing is
// returned unless every segment was re-encrypted. The object is held in memory, twice (the old and the new);
// ReEncryptStream holds a few batches of it.
func (c *Client) ReEncryptObject(ctx context.Context, profile string, object []byte, opts ...CallOption) ([]byte, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.reencryptObject(ctx, object, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.ReEncryptBatch(ctx, profile, items)
	})
}

// ReEncryptObject is Client.ReEncryptObject for the tenant: in a wrapped profile every segment moves to the tenant key
// blob to (as Tenant.ReEncrypt: the tenant's new key, or the handle's own blob); in a derived one to is nil.
func (t *Tenant) ReEncryptObject(ctx context.Context, object, to []byte, opts ...CallOption) ([]byte, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.reencryptObject(ctx, object, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return t.ReEncryptBatch(ctx, items, to)
	})
}
