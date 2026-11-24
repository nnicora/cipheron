package client

// stream.go — the segmented object format (transport/segment.go) over io.Reader and io.Writer: an object of any size
// encrypted and decrypted a group of segments at a time, up to pipelineDepth groups in flight (pipeline.go), so
// neither side holds more than about pipelineDepth batches of it in memory.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nnicora/cipheron/internal/zeroize"
	"github.com/nnicora/cipheron/wire/transport"
)

// streamGroup is how many segments of size segSize (with associated data of aadLen bytes) one batch of a stream
// carries: what inBatches would send in one batch, so a stream holds about pipelineDepth batches in memory.
func (c *Client) streamGroup(segSize, aadLen int) int {
	return c.groupOf(transport.SealedItemBytes(segSize, aadLen+transport.SegmentAssociatedDataOverhead))
}

// reencryptGroup is streamGroup for a re-encryption (ReEncryptBatch): each item counts its ciphertext — the segment's
// plaintext and at most a ciphertext's overhead — and both its associated data.
func (c *Client) reencryptGroup(segSize, aadLen, toAADLen int) int {
	return c.groupOf(int64(segSize) + int64(maxCiphertextOverhead()) +
		2*int64(transport.SegmentAssociatedDataOverhead) + int64(aadLen) + int64(toAADLen))
}

// groupOf is how many items of per bytes (as batch.maxBytes counts them) one batch carries: what inBatches would send
// in one batch.
func (c *Client) groupOf(per int64) int {
	maxBytes := min(int64(objectBatchBytes), int64(c.maxMessage-wireOverhead)*3/4) - int64(batchFixedBytes)
	return int(max(1, min(int64(objectBatchItems), maxBytes/max(1, per))))
}

// countingWriter counts what was written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

// encryptStream reads exactly size bytes of src, cuts them into segments of co's size and writes the segmented object
// to dst as it goes, encrypting a group of segments per batch through call. size is needed up front: the object's
// header names its segment count, and the last segment is made final. It returns the bytes written to dst.
func (c *Client) encryptStream(ctx context.Context, dst io.Writer, src io.Reader, size int64, co callOptions,
	call batchFunc) (int64, error) {
	if err := checkObjectAAD(co); err != nil {
		return 0, err
	}
	seg := co.segment
	if seg == 0 {
		seg = transport.DefaultSegmentSize
	}
	if seg < transport.MinSegmentSize || seg > transport.MaxSegmentSize {
		return 0, fmt.Errorf("cipheron: a segment size is %d to %d bytes, not %d", transport.MinSegmentSize,
			transport.MaxSegmentSize, seg)
	}
	if size < 0 {
		return 0, status.Errorf(codes.InvalidArgument, "cipheron: a stream's size is %d bytes", size)
	}
	if err := c.checkSegmentFits(seg, len(co.aad)); err != nil {
		return 0, err
	}
	count := max(1, (size+int64(seg)-1)/int64(seg))
	if count > transport.MaxSegments {
		return 0, fmt.Errorf("%w: %d segments of %d bytes; an object has at most %d (WithSegmentSize)", ErrTooLarge,
			count, seg, transport.MaxSegments)
	}
	id := make([]byte, transport.ObjectIDLen)
	_, _ = rand.Read(id) // crypto/rand.Read never fails; it crashes the program instead
	h := transport.SegmentedHeader{ObjectID: id, SegmentSize: uint32(seg), Count: uint32(count)}
	header, err := transport.AppendSegmentedHeader(transport.Release(), nil, h)
	if err != nil {
		return 0, err
	}
	out := &countingWriter{w: dst}
	if _, err := out.Write(header); err != nil {
		return out.n, err
	}
	group := c.streamGroup(seg, len(co.aad))
	read := int64(0)
	i := int64(0)
	// Up to pipelineDepth groups in flight (pipelined): the next group is read while the ones before it are
	// encrypted, and each is written in order once its batch answered. A read that fails stops reading; what is in
	// flight is written first, as the sequential loop had written it before reaching that read.
	err = pipelined(ctx, func() (func(context.Context) ([][]byte, error), error) {
		if i >= count {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		n := min(count-i, int64(group))
		want := min(n*int64(seg), size-read)
		buf := make([]byte, want) // the group's plaintext in one buffer, each segment a slice of it
		if _, err := io.ReadFull(src, buf); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, status.Errorf(codes.InvalidArgument, "cipheron: the stream ended before the %d bytes given as its size", size)
			}
			return nil, err
		}
		read += want
		items := make([]BatchItem, 0, n)
		for off := int64(0); off < want || (want == 0 && len(items) == 0); off += int64(seg) {
			items = append(items, BatchItem{Data: buf[off:min(off+int64(seg), want)],
				AssociatedData: transport.SegmentAssociatedData(id, uint32(i), i == count-1, co.aad)})
			i++
		}
		return func(ctx context.Context) ([][]byte, error) {
			cts, err := c.inBatches(ctx, items, true, call)
			return cts, segmentRefused(err, seg, true)
		}, nil
	}, func(cts [][]byte, err error) error {
		if err != nil {
			return err
		}
		total := 0
		for _, ct := range cts {
			total += 4 + len(ct)
		}
		b := make([]byte, 0, total) // the group's segments, framed, in one buffer sized once
		for _, ct := range cts {
			b = transport.AppendSegment(b, ct)
		}
		_, err = out.Write(b)
		return err
	}, func([][]byte) {})
	if err != nil {
		return out.n, err
	}
	// The size was the stream's: one byte more is an error (what was written is the object of the first size bytes).
	var one [1]byte
	if n, _ := io.ReadFull(src, one[:]); n > 0 {
		return out.n, status.Errorf(codes.InvalidArgument, "cipheron: the stream holds more than the %d bytes given as its size", size)
	}
	return out.n, nil
}

// decryptStream reads a segmented object from src and writes its plaintext to dst a group of segments at a time,
// each segment decrypted as its own position's. It returns the plaintext bytes written.
func (c *Client) decryptStream(ctx context.Context, dst io.Writer, src io.Reader, co callOptions, call batchFunc) (int64, error) {
	if err := checkObjectAAD(co); err != nil {
		return 0, err
	}
	h, err := transport.ReadSegmentedHeader(transport.Release(), src)
	if err != nil {
		return 0, err
	}
	out := &countingWriter{w: dst}
	group := c.streamGroup(int(h.SegmentSize), len(co.aad))
	type decrypted struct {
		start uint32
		pts   [][]byte
	}
	wipe := func(pts [][]byte) {
		for _, p := range pts {
			zeroize.Bytes(p)
		}
	}
	i := uint32(0)
	// Up to pipelineDepth groups in flight (pipelined), written in order: a segment is written only once every
	// segment before it was, each checked as its own position's, exactly as group after group.
	err = pipelined(ctx, func() (func(context.Context) (decrypted, error), error) {
		if i >= h.Count {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		start := i
		items := make([]BatchItem, 0, min(int(h.Count-i), group))
		for ; i < h.Count && len(items) < group; i++ {
			s, err := transport.ReadSegment(src, h)
			if err != nil {
				return nil, err
			}
			items = append(items, BatchItem{Data: s, AssociatedData: transport.SegmentAssociatedData(h.ObjectID, i,
				i == h.Count-1, co.aad)})
		}
		return func(ctx context.Context) (decrypted, error) {
			pts, err := c.inBatches(ctx, items, false, call)
			return decrypted{start: start, pts: pts}, segmentRefused(err, int(h.SegmentSize), false)
		}, nil
	}, func(g decrypted, err error) error {
		var f *segmentError
		if errors.As(err, &f) && integrityFailure(f.err) {
			return fmt.Errorf("%w: segment %d: %w", transport.ErrSegmented, int(g.start)+f.index, f.err)
		}
		if err != nil {
			return err
		}
		defer wipe(g.pts) // written (the writer keeps no reference: io.Writer), or refused
		for k, p := range g.pts {
			idx := g.start + uint32(k)
			last := idx == h.Count-1
			if (!last && len(p) != int(h.SegmentSize)) || len(p) > int(h.SegmentSize) || (last && len(p) == 0 && h.Count > 1) {
				return fmt.Errorf("%w: segment %d holds %d bytes, and the object's segments hold %d",
					transport.ErrSegmented, idx, len(p), h.SegmentSize)
			}
			if _, err := out.Write(p); err != nil {
				return err
			}
		}
		return nil
	}, func(g decrypted) { wipe(g.pts) })
	if err != nil {
		return out.n, err
	}
	var one [1]byte
	if n, _ := io.ReadFull(src, one[:]); n > 0 {
		return out.n, fmt.Errorf("%w: bytes follow the object's last segment", transport.ErrSegmented)
	}
	return out.n, nil
}

// reencryptStream reads a segmented object from src and writes, to dst, the object again — the same object id, segment
// size and count — each segment re-encrypted inside cipheron (call: ReEncryptBatch) as its own position's, a group of
// segments at a time: no plaintext reaches this client, and every segment keeps its binding (the object id is in its
// associated data: a re-encryption keeps the associated data). It returns the bytes written to dst.
func (c *Client) reencryptStream(ctx context.Context, dst io.Writer, src io.Reader, co callOptions, call batchFunc) (int64, error) {
	if err := checkReEncryptAAD(co); err != nil {
		return 0, err
	}
	h, err := transport.ReadSegmentedHeader(transport.Release(), src)
	if err != nil {
		return 0, err
	}
	if err := checkKeptSegmentSize(co, h); err != nil {
		return 0, err
	}
	header, err := transport.AppendSegmentedHeader(transport.Release(), nil,
		transport.SegmentedHeader{ObjectID: h.ObjectID, SegmentSize: h.SegmentSize, Count: h.Count})
	if err != nil {
		return 0, err
	}
	out := &countingWriter{w: dst}
	if _, err := out.Write(header); err != nil {
		return out.n, err
	}
	group := c.reencryptGroup(int(h.SegmentSize), len(co.aad), len(co.toAAD))
	type reencrypted struct {
		start uint32
		cts   [][]byte
	}
	i := uint32(0)
	// Up to pipelineDepth groups in flight (pipelined), written in order: a segment is written only once every segment
	// before it was, each re-encrypted as its own position's — exactly as group after group. A segment refused before
	// it is sent (its size, its bytes) stops the reading: what is in flight is written first.
	err = pipelined(ctx, func() (func(context.Context) (reencrypted, error), error) {
		if i >= h.Count {
			return nil, nil //nolint:nilnil // pipelined's contract: a nil job is the end of the source
		}
		start := i
		items := make([]BatchItem, 0, min(int(h.Count-i), group))
		for ; i < h.Count && len(items) < group; i++ {
			s, err := transport.ReadSegment(src, h)
			if err != nil {
				return nil, err
			}
			if err := segmentFits(h, i, s); err != nil {
				return nil, err
			}
			items = append(items, reencryptItem(h, i, s, co))
		}
		return func(ctx context.Context) (reencrypted, error) {
			cts, err := c.inBatches(ctx, items, false, call)
			return reencrypted{start: start, cts: cts}, segmentRefused(err, int(h.SegmentSize), false)
		}, nil
	}, func(g reencrypted, err error) error {
		var f *segmentError
		if errors.As(err, &f) && integrityFailure(f.err) {
			return fmt.Errorf("%w: segment %d: %w", transport.ErrSegmented, int(g.start)+f.index, f.err)
		}
		if err != nil {
			return err
		}
		total := 0
		for _, ct := range g.cts {
			total += 4 + len(ct)
		}
		b := make([]byte, 0, total) // the group's segments, framed, in one buffer sized once
		for _, ct := range g.cts {
			b = transport.AppendSegment(b, ct)
		}
		_, err = out.Write(b)
		return err
	}, func(reencrypted) {})
	if err != nil {
		return out.n, err
	}
	var one [1]byte
	if n, _ := io.ReadFull(src, one[:]); n > 0 {
		return out.n, fmt.Errorf("%w: bytes follow the object's last segment", transport.ErrSegmented)
	}
	return out.n, nil
}

// EncryptStream is EncryptObject over a stream: it reads exactly size bytes of src (the object's size, needed up
// front: the header names the segment count and the last segment is made final) and writes the segmented object to
// dst as it goes — the same bytes EncryptObject makes of the same plaintext, but with up to pipelineDepth batches of
// segments in memory at a time. It returns the bytes written to dst. A src shorter than size fails (INVALID_ARGUMENT: package cipheron's ErrInvalidInput), and so does one
// longer — what was written is then the object of the first size bytes: discard it. On any error what was written to
// dst is not an object to keep.
func (c *Client) EncryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, size int64,
	opts ...CallOption) (int64, error) {
	co, err := callOpts(opts)
	if err != nil {
		return 0, err
	}
	return c.encryptStream(ctx, dst, src, size, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.EncryptBatch(ctx, profile, items)
	})
}

// DecryptStream is DecryptObject over a stream: it reads a segmented object (EncryptObject's or EncryptStream's) from
// src and writes its plaintext to dst a batch of segments at a time, returning the plaintext bytes written. Every
// segment written was decrypted as its own position's in THIS object — none is ever written out of order or from
// another object — but a stream is verified as it goes: an object truncated, extended or tampered with further on
// fails only when that point is reached (transport.ErrSegmented in the chain), after the plaintext before it was
// written. On any error, discard what was written to dst; use DecryptObject when nothing may be released before the
// whole object is verified.
func (c *Client) DecryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	co, err := callOpts(opts)
	if err != nil {
		return 0, err
	}
	return c.decryptStream(ctx, dst, src, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.DecryptBatch(ctx, profile, items)
	})
}

// EncryptStream is Client.EncryptStream for the tenant.
func (t *Tenant) EncryptStream(ctx context.Context, dst io.Writer, src io.Reader, size int64, opts ...CallOption) (int64, error) {
	co, err := callOpts(opts)
	if err != nil {
		return 0, err
	}
	return t.c.encryptStream(ctx, dst, src, size, co, t.EncryptBatch)
}

// DecryptStream is Client.DecryptStream for the tenant.
func (t *Tenant) DecryptStream(ctx context.Context, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	co, err := callOpts(opts)
	if err != nil {
		return 0, err
	}
	return t.c.decryptStream(ctx, dst, src, co, t.DecryptBatch)
}

// ReEncryptStream is ReEncryptObject over a stream: it reads a segmented object of a shared profile from src and writes
// the re-encrypted object to dst as it goes — the same object ReEncryptObject makes, with up to pipelineDepth batches
// of segments in memory at a time instead of the whole object — and returns the bytes written to dst. No plaintext
// reaches this client (the caller's entry needs the reencrypt operation only: the object keeps its id and every
// segment its binding). A segment that does not re-encrypt as
// its own position's, or holds another size than its place holds, fails the stream when it is reached
// (transport.ErrSegmented in the chain), and so do bytes after the last segment: on any error, what was written to dst
// is not an object to keep — discard it. WithAssociatedData needs WithTargetAssociatedData equal to it, as
// ReEncryptObject's: refused before anything is read or sent (reencryptOpts).
func (c *Client) ReEncryptStream(ctx context.Context, profile string, dst io.Writer, src io.Reader, opts ...CallOption) (int64, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return 0, err
	}
	return c.reencryptStream(ctx, dst, src, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.ReEncryptBatch(ctx, profile, items)
	})
}

// ReEncryptStream is Client.ReEncryptStream for the tenant: in a wrapped profile every segment moves to the tenant key
// blob to (as Tenant.ReEncrypt); in a derived one to is nil.
func (t *Tenant) ReEncryptStream(ctx context.Context, dst io.Writer, src io.Reader, to []byte, opts ...CallOption) (int64, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return 0, err
	}
	return t.c.reencryptStream(ctx, dst, src, co, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return t.ReEncryptBatch(ctx, items, to)
	})
}
