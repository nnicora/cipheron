package transport

import "testing"

// TestARefusalIsClassifiedByCodeAndCipheronsReasonOnly: the class and retry rule of every refusal cipheron answers,
// and of what looks like one: a reason counts only in cipheron's ErrorInfo domain and with the code cipheron answers
// it with; UNAVAILABLE is transient only without an ErrorInfo or with one of the transient reasons; the start
// barrier's refusal is re-signed whatever the operation.
func TestARefusalIsClassifiedByCodeAndCipheronsReasonOnly(t *testing.T) {
	ours := func(code uint32, reason string) Refusal {
		return Refusal{Code: code, HasErrorInfo: true, ErrorDomain: ErrorDomain, Reason: reason}
	}
	for _, c := range []struct {
		name  string
		r     Refusal
		class RefusalClass
		rule  RetryRule
	}{
		{"permission", Refusal{Code: codePermissionDenied}, ClassPermissionDenied, RetryNever},
		{"busy on permission", ours(codePermissionDenied, ReasonBusy), ClassPermissionDenied, RetryNever},
		{"invalid", Refusal{Code: codeInvalidArgument}, ClassInvalidInput, RetryNever},
		{"key version", ours(codeInvalidArgument, ReasonKeyVersionUnavailable), ClassKeyVersionUnavailable, RetryNever},
		{"key version of another domain", Refusal{Code: codeInvalidArgument, HasErrorInfo: true, ErrorDomain: "x",
			Reason: ReasonKeyVersionUnavailable}, ClassInvalidInput, RetryNever},
		{"associated data", ours(codeInvalidArgument, ReasonAssociatedData), ClassAssociatedData, RetryNever},
		{"batch limit", ours(codeInvalidArgument, ReasonBatchLimit), ClassBatchLimit, RetryNever},
		{"busy", ours(codeResourceExhausted, ReasonBusy), ClassBusy, RetryTransient},
		{"exhausted", Refusal{Code: codeResourceExhausted}, ClassResourceExhausted, RetryNever},
		{"busy of another domain", Refusal{Code: codeResourceExhausted, HasErrorInfo: true, ErrorDomain: "proxy",
			Reason: ReasonBusy}, ClassResourceExhausted, RetryNever},
		{"starting", ours(codeUnavailable, ReasonStarting), ClassStarting, RetryResign},
		{"starting on invalid", ours(codeInvalidArgument, ReasonStarting), ClassInvalidInput, RetryNever},
		{"starting of another domain", Refusal{Code: codeUnavailable, HasErrorInfo: true, ErrorDomain: "proxy",
			Reason: ReasonStarting}, ClassUnavailable, RetryNever},
		{"no writer", ours(codeUnavailable, ReasonNoWriter), ClassNoWriter, RetryTransient},
		{"sealed", ours(codeUnavailable, ReasonProfileSealed), ClassProfileSealed, RetryTransient},
		{"audit", ours(codeUnavailable, ReasonAuditUnavailable), ClassAuditUnavailable, RetryTransient},
		{"connection lost", Refusal{Code: codeUnavailable}, ClassUnavailable, RetryTransient},
		{"unknown reason", ours(codeUnavailable, "CIPHERON_SOMETHING"), ClassUnavailable, RetryNever},
		{"empty reason", ours(codeUnavailable, ""), ClassUnavailable, RetryNever},
		{"unimplemented", Refusal{Code: codeUnimplemented}, ClassUnsupported, RetryNever},
		{"internal", Refusal{Code: codeInternal}, ClassInternal, RetryNever},
		{"not found", Refusal{Code: 5}, ClassOther, RetryNever},
		{"deadline", ours(4, ReasonBusy), ClassOther, RetryNever},
	} {
		if class, rule := c.r.Classify(); class != c.class || rule != c.rule {
			t.Errorf("%s: %s, %s; want %s, %s", c.name, class, rule, c.class, c.rule)
		}
	}
}
