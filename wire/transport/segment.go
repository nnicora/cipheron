package transport

// segment.go — the segmented large-object format a client writes for an object too large for one request: the
// object is cut into segments, each encrypted by cipheron (through the batch operations) as a ciphertext made with
// associated data (format 5 or 6) that names the object, the segment's index and whether it is the last one. The
// container is the client's; cipheron sees only ordinary ciphertexts with associated data.
//
//	"CPS1" | version 1 | object id (16) | segment size (4) | count (4) | count × ( length (4) | ciphertext )
//
// (every number big-endian). Segment i's associated data (SegmentAssociatedData) is
//
//	lp("cipheron/v1|segment") lp(object id) lp(i: 4 bytes) lp(final: 1 byte, 1 for the last segment, 0 otherwise)
//	lp(the caller's associated data)
//
// so a reader that decrypts segment i of a container as (object id of the container, i, i == count-1) detects:
// segments reordered (another index), a container truncated (its new last segment was not made final), extended or
// spliced with a segment of another object (another object id) or of another position, and associated data that
// is not the caller's. The object id is random (16 bytes): two objects never share one. The segment size is checked
// against what decrypted (every segment but the last holds exactly that many bytes, the last one to that many).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/nnicora/cipheron/wire/format"
)

const (
	// SegmentedMagic opens a segmented object.
	SegmentedMagic = "CPS1"
	// SegmentedVersion is the container's version.
	SegmentedVersion byte = 1
	// ObjectIDLen is the length of a segmented object's id.
	ObjectIDLen = 16
	// SegmentedHeaderLen is the container's header: magic, version, object id, segment size and count (29).
	SegmentedHeaderLen = len(SegmentedMagic) + 1 + ObjectIDLen + 4 + 4
	// MinSegmentSize and MaxSegmentSize bound a segment's plaintext size (DefaultSegmentSize between them).
	MinSegmentSize     = 1 << 10
	MaxSegmentSize     = 16 << 20
	DefaultSegmentSize = 64 << 10
	// MaxSegments bounds a container's segment count.
	MaxSegments = 1 << 20
	// MaxSegmentOverhead bounds what a segment's ciphertext adds to its plaintext (formats 5 and 6 add at most about
	// a hundred bytes): a streaming reader refuses a segment longer than the header's size and this (ReadSegment).
	MaxSegmentOverhead = 1 << 10
)

// segmentLabel opens a segment's associated data.
var segmentLabel = format.LabelSegment.String()

// segmentLabelLen is segmentLabel's length as a constant, which the overhead below is: initialisation refuses a
// label of another length (a namespace of another length) rather than an overhead that does not hold.
const segmentLabelLen = 19

func init() {
	if len(segmentLabel) != segmentLabelLen {
		panic(fmt.Sprintf("cipheron: the segment label %q is not %d bytes", segmentLabel, segmentLabelLen))
	}
}

// SegmentAssociatedDataOverhead is what SegmentAssociatedData adds to the caller's associated data (the label, the
// object id, the index and the final flag, each behind its length, and the caller's length): 60 bytes. A segment's
// associated data is bounded by MaxAssociatedDataLen like any, so an object's (the caller's) is at most
// MaxObjectAssociatedDataLen.
const SegmentAssociatedDataOverhead = 4 + segmentLabelLen + 4 + ObjectIDLen + 4 + 4 + 4 + 1 + 4

// MaxObjectAssociatedDataLen bounds the associated data of a segmented object (EncryptObject, EncryptStream):
// MaxAssociatedDataLen less SegmentAssociatedDataOverhead (65476 bytes).
const MaxObjectAssociatedDataLen = MaxAssociatedDataLen - SegmentAssociatedDataOverhead

// ErrSegmented is the refusal of bytes that are not a segmented object of this format, or whose segments do not
// decrypt as its own, in their order, ending with its last segment.
var ErrSegmented = errors.New("cipheron: not a segmented object, or one that was modified, truncated or reordered")

// SegmentAssociatedData is the associated data segment index of object objectID is encrypted with: the object, the
// index, whether it is the final segment, and the caller's associated data (empty: none).
func SegmentAssociatedData(objectID []byte, index uint32, final bool, aad []byte) []byte {
	f := [1]byte{0}
	if final {
		f[0] = 1
	}
	return newTranscript(len(segmentLabel), len(objectID), 4, len(f), len(aad)).
		addString(segmentLabel).add(objectID).addUint32(index).add(f[:]).add(aad)
}

// SegmentedHeader is a segmented object's header.
type SegmentedHeader struct {
	ObjectID    []byte
	SegmentSize uint32
	Count       uint32
}

// MarshalSegmented writes a segmented object: h's header, then each segment ciphertext behind its length. It
// refuses a header that is not valid or a count that is not len(segments).
func MarshalSegmented(p *format.Policy, h SegmentedHeader, segments [][]byte) ([]byte, error) {
	w := format.Write(p, objects, 0)
	n := len(w.Marker()) + w.Codec().Size(h)
	for _, s := range segments {
		n += 4 + len(s)
	}
	out, err := format.AppendHeader(w, make([]byte, 0, n), h, nil)
	if err != nil {
		return nil, err
	}
	if int(h.Count) != len(segments) {
		return nil, fmt.Errorf("cipheron: a segmented object's count is %d, and %d segments are given", h.Count, len(segments))
	}
	for _, s := range segments {
		out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
		out = append(out, s...)
	}
	return out, nil
}

func (h SegmentedHeader) validate() error {
	switch {
	case len(h.ObjectID) != ObjectIDLen:
		return fmt.Errorf("cipheron: an object id is %d bytes", ObjectIDLen)
	case h.SegmentSize < MinSegmentSize || h.SegmentSize > MaxSegmentSize:
		return fmt.Errorf("cipheron: a segment size is %d to %d bytes", MinSegmentSize, MaxSegmentSize)
	case h.Count == 0 || h.Count > MaxSegments:
		return fmt.Errorf("cipheron: a segmented object has 1 to %d segments", MaxSegments)
	}
	return nil
}

// IsSegmented reports whether b opens like a segmented object (its magic and a version p reads); ParseSegmented checks
// the rest.
func IsSegmented(p *format.Policy, b []byte) bool {
	_, err := format.Marked(p, objects, b)
	return err == nil
}

// ParseSegmented reads a segmented object: its header and its segment ciphertexts (sub-slices of b), every byte of
// b accounted for. It decrypts nothing: a reader decrypts segment i with SegmentAssociatedData(h.ObjectID, i,
// i == h.Count-1, its associated data). Anything else is ErrSegmented.
func ParseSegmented(policy *format.Policy, b []byte) (SegmentedHeader, [][]byte, error) {
	s, err := format.Marked(policy, objects, b)
	if err != nil {
		return SegmentedHeader{}, nil, ErrSegmented
	}
	var h SegmentedHeader
	p, ok := format.ParseHeader(s, b, &h)
	if !ok {
		return SegmentedHeader{}, nil, ErrSegmented
	}
	// No allocation sized by the unverified count beyond what the bytes can hold: each segment takes at least 4.
	if uint64(h.Count)*4 > uint64(len(b)-p) {
		return SegmentedHeader{}, nil, ErrSegmented
	}
	segs := make([][]byte, 0, h.Count)
	for i := uint32(0); i < h.Count; i++ {
		if len(b)-p < 4 {
			return SegmentedHeader{}, nil, ErrSegmented
		}
		n := binary.BigEndian.Uint32(b[p:])
		p += 4
		if uint64(n) > uint64(len(b)-p) {
			return SegmentedHeader{}, nil, ErrSegmented
		}
		segs = append(segs, b[p:p+int(n)])
		p += int(n)
	}
	if p != len(b) {
		return SegmentedHeader{}, nil, ErrSegmented
	}
	return h, segs, nil
}

// AppendSegmentedHeader appends h's header — what MarshalSegmented writes before the segments, in the scheme p writes
// — to dst: for a writer that streams the segments (AppendSegment) instead of holding them all. It refuses a header
// that is not valid.
func AppendSegmentedHeader(p *format.Policy, dst []byte, h SegmentedHeader) ([]byte, error) {
	return format.AppendHeader(format.Write(p, objects, 0), dst, h, nil)
}

// AppendSegment appends one segment ciphertext behind its length, as MarshalSegmented writes each.
func AppendSegment(dst, segment []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(segment)))
	return append(dst, segment...)
}

// ReadSegmentedHeader reads a segmented object's header from r (a streaming reader: ReadSegment then reads its
// segments one by one): the shortest header of the schemes p reads, then — when the scheme its magic and version name
// has a longer one — the rest of it, and not a byte more. Anything that is not a valid header is ErrSegmented.
func ReadSegmentedHeader(p *format.Policy, r io.Reader) (SegmentedHeader, error) {
	minHeader, _, _ := format.Bounds(p, objects)
	b := make([]byte, minHeader)
	if err := readFullSegmented(r, b); err != nil {
		return SegmentedHeader{}, err
	}
	s, err := format.Marked(p, objects, b)
	if err != nil {
		return SegmentedHeader{}, ErrSegmented
	}
	if n, _, _ := s.Bounds(); n > len(b) {
		have := len(b)
		full := make([]byte, n)
		copy(full, b)
		if err := readFullSegmented(r, full[have:]); err != nil {
			return SegmentedHeader{}, err
		}
		b = full
	}
	var h SegmentedHeader
	if _, ok := format.ParseHeader(s, b, &h); !ok {
		return SegmentedHeader{}, ErrSegmented
	}
	return h, nil
}

// readFullSegmented fills b from r: an object that ends early is ErrSegmented, any other error r's.
func readFullSegmented(r io.Reader, b []byte) error {
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrSegmented
		}
		return err
	}
	return nil
}

// ReadSegment reads the next segment ciphertext of an object whose header is h from r: its length, at most
// h.SegmentSize + MaxSegmentOverhead (nothing is allocated by a longer claim), and its bytes. An object that ends
// early is ErrSegmented.
func ReadSegment(r io.Reader, h SegmentedHeader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrSegmented
		}
		return nil, err
	}
	l := binary.BigEndian.Uint32(n[:])
	if uint64(l) > uint64(h.SegmentSize)+MaxSegmentOverhead {
		return nil, ErrSegmented
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrSegmented
		}
		return nil, err
	}
	return b, nil
}
