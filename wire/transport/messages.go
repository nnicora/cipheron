package transport

// messages.go — the messages of cipheron's refusals that the test server (cipherontest) gives too, word for word:
// one definition, so a client or a test that reads a message (a person does; a client decides on the reason) sees
// the same text from both. And the HTTP gateway's two forwarded headers, and how an HTTP body is read.

import (
	"io"
	"strconv"
	"strings"
)

// The associated-data refusals.
var (
	// AssociatedDataMessage is INVALID_ARGUMENT with ReasonAssociatedData: a ciphertext opened with other associated
	// data than it was made with, or associated data over MaxAssociatedDataLen.
	AssociatedDataMessage = "the associated data does not match the ciphertext: a ciphertext made with associated data " +
		"(format 5 or 6) is decrypted with it, one made without (format 3 or 4) without any; associated data is at " +
		"most " + strconv.Itoa(MaxAssociatedDataLen) + " bytes"
	// TargetAssociatedDataMessage is INVALID_ARGUMENT with ReasonAssociatedData: a re-encryption (a ReEncrypt, or an
	// item of a ReEncryptBatch) with associated_data and no to_associated_data (CheckReEncryptAssociatedData).
	TargetAssociatedDataMessage = "associated_data without to_associated_data: a re-encryption does not drop the " +
		"associated data; send the same bytes as to_associated_data to keep it"
)

// EmptyBatchMessage is INVALID_ARGUMENT: a batch without items.
const EmptyBatchMessage = "a batch holds at least one item"

// TooManyItemsMessage is INVALID_ARGUMENT (no ErrorInfo): a batch of more than MaxBatchItems items, refused before
// it is decoded, the same answer to every caller on both protocols. No configuration allows such a batch, so the
// answer names no configured limit; a batch within MaxBatchItems and over batch.maxItems is ReasonBatchLimit's.
var TooManyItemsMessage = "the batch holds more than " + strconv.Itoa(MaxBatchItems) + " items, which no batch " +
	"may hold: split it"

// BatchLimitMessage is INVALID_ARGUMENT with ReasonBatchLimit (metadata maxItems, maxBytes): a batch of items items
// and bytes payload bytes (BatchBytes) over the limits.
func BatchLimitMessage(items int, bytes int64, maxItems int, maxBytes int64) string {
	return "the batch holds " + strconv.Itoa(items) + " items and " + strconv.FormatInt(bytes, 10) + " payload bytes; " +
		"this cipheron accepts at most " + strconv.Itoa(maxItems) + " items and " + strconv.FormatInt(maxBytes, 10) +
		" bytes (batch.maxItems, batch.maxBytes): split it"
}

// The HTTP gateway's refusals.
const (
	// QueryStringMessage is INVALID_ARGUMENT (HTTP 400): a request with a query string.
	QueryStringMessage = "the request has a query string: the API takes no query parameters"
	// ProfileMismatchMessage is INVALID_ARGUMENT (HTTP 400): a body naming another profile than the request path.
	ProfileMismatchMessage = "the request body's profile differs from the profile in the request path"
	// TooLargeMessage is RESOURCE_EXHAUSTED (HTTP 413, no detail): a request beyond the listener's maxRequestBytes —
	// received, or declared (RequestBytesMetadataKey, Content-Length) and refused before it is read.
	TooLargeMessage = "received message larger than max: the request exceeds the listener's maxRequestBytes"
	// UndeclaredTooLargeMessage is RESOURCE_EXHAUSTED (HTTP 413, no detail): a request that declares no size, beyond
	// the listener's undeclaredMaxRequestBytes. Its wording carries gRPC's ("larger than max"), as TooLargeMessage's
	// does: a client that reads the status alone tells a size refusal by it.
	UndeclaredTooLargeMessage = "received message larger than max: a request that declares no size (" +
		RequestBytesMetadataKey + " over gRPC, Content-Length over HTTP) is at most the listener's " +
		"undeclaredMaxRequestBytes"
)

// THE REQUEST-SIZE DECLARATION. cipheron admits a request against its listener's memory budget by the request's size
// before it reads the request's message — gRPC reads a message's length and its body in one step, with nothing in
// between — so a request declares its size where cipheron reads it at admission: over gRPC in the metadata
// RequestBytesMetadataKey, the decimal number of bytes of its message as sent (its protobuf encoding); over HTTP its
// body's Content-Length. A request that declares none is held to the listener's undeclaredMaxRequestBytes and
// reserved at that size.
const (
	// RequestBytesMetadataKey is the gRPC metadata key a request's declared size travels in: one value, decimal
	// digits with no sign and no leading zero, 1 or more (ParseRequestBytes).
	RequestBytesMetadataKey = "cipheron-request-bytes"
	// MalformedDeclarationMessage is INVALID_ARGUMENT (no detail), before the message is read: a declaration that is
	// not one decimal number of bytes, 1 or more.
	MalformedDeclarationMessage = "the request's size declaration (" + RequestBytesMetadataKey + ") is not one " +
		"decimal number of bytes, 1 or more"
	// OverDeclaredMessage is INVALID_ARGUMENT (no detail): a request message larger than its declared size.
	OverDeclaredMessage = "the request message is larger than its declared size (" + RequestBytesMetadataKey + ")"
)

// maxRequestBytesDigits bounds a declaration's digits: an int64 has 19.
const maxRequestBytesDigits = 19

// ParseRequestBytes reads a declared size (RequestBytesMetadataKey's value): decimal digits only — no sign, no space,
// no leading zero —, 1 or more, at most what an int64 holds. ok is false for anything else.
func ParseRequestBytes(v string) (n int64, ok bool) {
	if len(v) == 0 || len(v) > maxRequestBytesDigits || v[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

// HTTPBodyLimit is the most bytes an HTTP request's JSON body may have on a listener whose messages are bounded by
// maxRequest bytes: the bytes fields travel in base64 (4 characters for 3 bytes), with HTTPJSONHeadroom for the
// names, the punctuation, the other fields and a client encoder's whitespace. The decoded message is then held to
// maxRequest itself.
func HTTPBodyLimit(maxRequest int64) int64 { return maxRequest + (maxRequest+2)/3 + HTTPJSONHeadroom }

// HTTPMessageBytes is HTTPBodyLimit's inverse: the size of message a JSON body of bodyLen bytes declares — the
// smallest maxRequest whose HTTPBodyLimit admits the body (0 for a body within HTTPJSONHeadroom). A body of
// bodyLen bytes is within a listener's bound exactly when HTTPMessageBytes(bodyLen) is within its maxRequestBytes;
// it is what an HTTP request is reserved at against the memory budget.
func HTTPMessageBytes(bodyLen int64) int64 {
	if bodyLen <= HTTPJSONHeadroom {
		return 0
	}
	m := (bodyLen - HTTPJSONHeadroom) * 3 / 4
	for HTTPBodyLimit(m) < bodyLen {
		m++
	}
	for m > 0 && HTTPBodyLimit(m-1) >= bodyLen {
		m--
	}
	return m
}

// ReadHTTPBody reads r — an HTTP body of size bytes as its Content-Length announced (-1: not announced) — whole, and
// at most limit+1 bytes of it: the caller refuses more than limit (it reads one byte beyond, to know). It is
// io.ReadAll(io.LimitReader(r, limit+1)) with the buffer sized once from the announced length when that is within
// limit — one allocation instead of io.ReadAll's growth by doubling — and grown as io.ReadAll does when the body runs
// past it (still bounded by limit+1). The announcement only sizes the buffer: it is trusted for nothing else.
func ReadHTTPBody(r io.Reader, size, limit int64) ([]byte, error) {
	if size < 0 || size > limit {
		return io.ReadAll(io.LimitReader(r, limit+1))
	}
	lr := io.LimitReader(r, limit+1)
	b := make([]byte, 0, size+1) // one byte beyond: the read that finds the end needs room to be made
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
		n, err := lr.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
	}
}

// HTTPJSONHeadroom is what an HTTP request's JSON body may hold beyond its bytes fields in base64.
const HTTPJSONHeadroom = 4 << 10

// The two HTTP headers the gateway turns into gRPC metadata (GatewayHeader), canonical, and the metadata keys they
// become — what a gRPC caller sends as x-request-id (the audit event's request id) and traceparent (the request
// span's link).
const (
	HTTPRequestIDHeader    = "Grpc-Metadata-X-Request-Id"
	HTTPTraceparentHeader  = "Grpc-Metadata-Traceparent"
	RequestIDMetadataKey   = "x-request-id"
	TraceparentMetadataKey = "traceparent"
)

// GatewayHeader is the HTTP gateway's incoming header matcher: HTTPRequestIDHeader becomes RequestIDMetadataKey and
// HTTPTraceparentHeader becomes TraceparentMetadataKey (compared without regard to case); every other header is
// dropped.
func GatewayHeader(key string) (string, bool) {
	switch {
	case strings.EqualFold(key, HTTPRequestIDHeader):
		return RequestIDMetadataKey, true
	case strings.EqualFold(key, HTTPTraceparentHeader):
		return TraceparentMetadataKey, true
	}
	return "", false
}
