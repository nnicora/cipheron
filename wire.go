package cipheron

// wire.go — the parts of the protocol an application works with directly: the operation names (what an audit event and
// a caller entry's grant name a call by), the gRPC metadata key a call's request id travels in, and the segmented
// object's framing for an application that stores a large object's segments itself and reads them back as a stream. The
// protocol's machinery behind them (package wire/transport) is for the server and for other implementations of the
// protocol, not for applications; this is what of it an application uses, in this release's formats.

import (
	"io"

	"github.com/nnicora/cipheron/wire/transport"
)

// Operation is the name of a cipheron operation: what an audit event's op and a caller entry's grant name it by.
type Operation = transport.Operation

// The operations. OpEncrypt, OpDecrypt, OpSign, OpReEncrypt, OpProvision, OpExport, OpImport and OpRetenant are what
// a caller entry may be given; the rest name calls in audit events.
const (
	OpEncrypt              = transport.OpEncrypt
	OpDecrypt              = transport.OpDecrypt
	OpSign                 = transport.OpSign
	OpReEncrypt            = transport.OpReEncrypt
	OpExport               = transport.OpExport
	OpImport               = transport.OpImport
	OpRetenant             = transport.OpRetenant
	OpProvision            = transport.OpProvision
	OpRewrapTenantKey      = transport.OpRewrapTenantKey
	OpEncryptBatch         = transport.OpEncryptBatch
	OpDecryptBatch         = transport.OpDecryptBatch
	OpReEncryptBatch       = transport.OpReEncryptBatch
	OpRewrapTenantKeyBatch = transport.OpRewrapTenantKeyBatch
)

// RequestIDMetadataKey is the gRPC metadata key a call's request id travels in (x-request-id): set it on a call's
// outgoing context to choose the id cipheron's audit event records for it (RequestIDOf reads it back from an error).
const RequestIDMetadataKey = transport.RequestIDMetadataKey

// SegmentedHeader is a segmented object's header (EncryptObject, EncryptStream): its object id, its segment size and
// its segment count.
type SegmentedHeader = transport.SegmentedHeader

const (
	// SegmentedHeaderLen is the length of a segmented object's header in the format this release writes.
	SegmentedHeaderLen = transport.SegmentedHeaderLen
	// MaxSegmentOverhead bounds what a segment's ciphertext adds to its plaintext (its header and tag).
	MaxSegmentOverhead = transport.MaxSegmentOverhead
)

// ReadSegmentedHeader reads a segmented object's header from r and checks it: one of a version this release reads.
func ReadSegmentedHeader(r io.Reader) (SegmentedHeader, error) {
	return transport.ReadSegmentedHeader(transport.Release(), r)
}

// AppendSegmentedHeader appends h's header, in the version this release writes, to dst.
func AppendSegmentedHeader(dst []byte, h SegmentedHeader) ([]byte, error) {
	return transport.AppendSegmentedHeader(transport.Release(), dst, h)
}

// ReadSegment reads the next segment of an object with header h from r: one length-prefixed ciphertext. A segment
// longer than h's segment size allows, or an object that ends early, is ErrSegmented.
func ReadSegment(r io.Reader, h SegmentedHeader) ([]byte, error) { return transport.ReadSegment(r, h) }

// AppendSegment appends segment, one segment's ciphertext, to dst behind its length: the framing ReadSegment reads.
func AppendSegment(dst, segment []byte) []byte { return transport.AppendSegment(dst, segment) }
