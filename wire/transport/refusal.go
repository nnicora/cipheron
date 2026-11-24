package transport

// refusal.go — what a client makes of a refusal: its class and its retry rule, from the status code, cipheron's
// google.rpc.ErrorInfo (its profile and reason) and nothing else. The message is for humans and is never read; the
// google.rpc.RetryInfo only bounds the wait before a retry the rule allows, it never makes a refusal retryable.
//
// A refusal is NOT SIGNED by the profile's response key (only answers are): it is as trustworthy as the connection
// that carried it, and no more. A client never deletes, quarantines or provisions anything again on a refusal alone:
// it asks again (another replica, another connection) or confirms with a signed operation.
//
// The Go client's retry decisions (internal/client, retry.go) are made here, and the conformance kit's errorClass
// kind is computed here, so a client of any language is held to the same table.

// RefusalClass is what a refusal says, as a client acts on it.
type RefusalClass string

// The classes.
const (
	// ClassPermissionDenied: PERMISSION_DENIED — not until the configuration changes.
	ClassPermissionDenied RefusalClass = "permissionDenied"
	// ClassInvalidInput: INVALID_ARGUMENT without a reason below — the same call fails the same way.
	ClassInvalidInput RefusalClass = "invalidInput"
	// ClassKeyVersionUnavailable: INVALID_ARGUMENT with ReasonKeyVersionUnavailable — the data is not lost: the version
	// is not listed (or not rolled out) on the replica that answered.
	ClassKeyVersionUnavailable RefusalClass = "keyVersionUnavailable"
	// ClassAssociatedData: INVALID_ARGUMENT with ReasonAssociatedData.
	ClassAssociatedData RefusalClass = "associatedData"
	// ClassBatchLimit: INVALID_ARGUMENT with ReasonBatchLimit.
	ClassBatchLimit RefusalClass = "batchLimit"
	// ClassBusy: RESOURCE_EXHAUSTED with ReasonBusy.
	ClassBusy RefusalClass = "busy"
	// ClassResourceExhausted: RESOURCE_EXHAUSTED without ReasonBusy — gRPC's refusal of a message over a size limit,
	// or something on the way shedding load.
	ClassResourceExhausted RefusalClass = "resourceExhausted"
	// ClassNoWriter: UNAVAILABLE with ReasonNoWriter.
	ClassNoWriter RefusalClass = "noWriter"
	// ClassProfileSealed: UNAVAILABLE with ReasonProfileSealed.
	ClassProfileSealed RefusalClass = "profileSealed"
	// ClassAuditUnavailable: UNAVAILABLE with ReasonAuditUnavailable.
	ClassAuditUnavailable RefusalClass = "auditUnavailable"
	// ClassStarting: UNAVAILABLE with ReasonStarting — the request was signed before the answering process started.
	ClassStarting RefusalClass = "starting"
	// ClassUnavailable: UNAVAILABLE with no ErrorInfo (the connection lost, a replica draining), or with a reason this
	// table does not have, or an ErrorInfo of another domain.
	ClassUnavailable RefusalClass = "unavailable"
	// ClassUnsupported: UNIMPLEMENTED.
	ClassUnsupported RefusalClass = "unsupported"
	// ClassInternal: INTERNAL.
	ClassInternal RefusalClass = "internal"
	// ClassOther: any other status code.
	ClassOther RefusalClass = "other"
)

// RetryRule is what a client may do after a refusal.
type RetryRule string

// The rules.
const (
	// RetryNever: the call is answered with the refusal.
	RetryNever RetryRule = "never"
	// RetryTransient: an idempotent call (never CreateTenantKey or RewrapTenantKey) may be sent again — a new request:
	// a fresh nonce, signed again — after a backoff no shorter than the RetryInfo.
	RetryTransient RetryRule = "transient"
	// RetryResign: nothing ran and nothing was recorded; the call, whatever its operation, is signed again (a new
	// timestamp and nonce) and sent once more after the RetryInfo.
	RetryResign RetryRule = "resign"
)

// The google.rpc.Code numbers a refusal is classified by.
const (
	codeInvalidArgument   uint32 = 3
	codePermissionDenied  uint32 = 7
	codeResourceExhausted uint32 = 8
	codeUnimplemented     uint32 = 12
	codeInternal          uint32 = 13
	codeUnavailable       uint32 = 14
)

// Refusal is what a client reads of a refusal: its google.rpc.Code number, and its google.rpc.ErrorInfo — HasErrorInfo
// false when it carries none; with several, the last one.
type Refusal struct {
	Code         uint32
	HasErrorInfo bool
	ErrorDomain  string
	Reason       string
}

// reason is r's cipheron reason: its ErrorInfo's reason when the ErrorInfo is cipheron's (ErrorDomain), else "".
func (r Refusal) reason() string {
	if r.HasErrorInfo && r.ErrorDomain == ErrorDomain {
		return r.Reason
	}
	return ""
}

// Classify is r's class and retry rule. A reason counts only in cipheron's ErrorInfo domain and only with the code
// cipheron answers it with (transport.go, Reason…): CIPHERON_BUSY on PERMISSION_DENIED is a permission refusal, never
// retried; an ErrorInfo of another domain is no reason of cipheron's.
func (r Refusal) Classify() (RefusalClass, RetryRule) {
	reason := r.reason()
	switch r.Code {
	case codePermissionDenied:
		return ClassPermissionDenied, RetryNever
	case codeInvalidArgument:
		switch reason {
		case ReasonKeyVersionUnavailable:
			return ClassKeyVersionUnavailable, RetryNever
		case ReasonAssociatedData:
			return ClassAssociatedData, RetryNever
		case ReasonBatchLimit:
			return ClassBatchLimit, RetryNever
		}
		return ClassInvalidInput, RetryNever
	case codeResourceExhausted:
		if reason == ReasonBusy {
			return ClassBusy, RetryTransient
		}
		return ClassResourceExhausted, RetryNever
	case codeUnavailable:
		switch {
		case reason == ReasonStarting:
			return ClassStarting, RetryResign
		case reason == ReasonNoWriter:
			return ClassNoWriter, RetryTransient
		case reason == ReasonProfileSealed:
			return ClassProfileSealed, RetryTransient
		case reason == ReasonAuditUnavailable:
			return ClassAuditUnavailable, RetryTransient
		case !r.HasErrorInfo:
			return ClassUnavailable, RetryTransient
		}
		return ClassUnavailable, RetryNever
	case codeUnimplemented:
		return ClassUnsupported, RetryNever
	case codeInternal:
		return ClassInternal, RetryNever
	}
	return ClassOther, RetryNever
}
