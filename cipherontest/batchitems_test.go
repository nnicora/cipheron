package cipherontest

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// TestTheFakeRefusesMoreThanMaxBatchItems: as cipheron (owner decision S1), a batch of more than
// transport.MaxBatchItems items is refused before anything else — whatever the profile, the grants or the auth —
// INVALID_ARGUMENT with transport.TooManyItemsMessage and no ErrorInfo (no configured limit named); a batch of
// MaxBatchItems is judged against the fake's limits as before (CIPHERON_BATCH_LIMIT).
func TestTheFakeRefusesMoreThanMaxBatchItems(t *testing.T) {
	s := New(t, "a")
	ctx := context.Background()
	calls := map[string]func(n int) error{
		"EncryptBatch": func(n int) error {
			_, err := s.EncryptBatch(ctx, &cipheronv1.EncryptBatchRequest{Profile: "nowhere",
				Items: make([]*cipheronv1.EncryptBatchItem, n)})
			return err
		},
		"DecryptBatch": func(n int) error {
			_, err := s.DecryptBatch(ctx, &cipheronv1.DecryptBatchRequest{Profile: "nowhere",
				Items: make([]*cipheronv1.DecryptBatchItem, n)})
			return err
		},
		"ReEncryptBatch": func(n int) error {
			_, err := s.ReEncryptBatch(ctx, &cipheronv1.ReEncryptBatchRequest{Profile: "nowhere",
				Items: make([]*cipheronv1.ReEncryptBatchItem, n)})
			return err
		},
		"RewrapTenantKeyBatch": func(n int) error {
			_, err := s.RewrapTenantKeyBatch(ctx, &cipheronv1.RewrapTenantKeyBatchRequest{Profile: "nowhere",
				Items: make([]*cipheronv1.RewrapTenantKeyBatchItem, n)})
			return err
		},
	}
	for name, call := range calls {
		st := status.Convert(call(transport.MaxBatchItems + 1))
		if st.Code() != codes.InvalidArgument || st.Message() != transport.TooManyItemsMessage || len(st.Details()) != 0 {
			t.Errorf("%s of %d items: %v %v, want INVALID_ARGUMENT %q with no detail", name, transport.MaxBatchItems+1,
				st.Err(), st.Details(), transport.TooManyItemsMessage)
		}
		if st := status.Convert(call(transport.MaxBatchItems)); st.Message() == transport.TooManyItemsMessage {
			t.Errorf("%s of %d items refused as too many", name, transport.MaxBatchItems)
		}
	}
}
