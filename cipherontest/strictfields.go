package cipherontest

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// strictFields is the fake's gRPC refusal of a request carrying a field the API does not have, as cipheron's server
// answers it (the server's strictfields.go): INVALID_ARGUMENT naming the field's number and the message
// it is in, before the service sees the request — the HTTP side already refuses an unknown JSON field
// (HTTPHandler). Without it, a client change that sends a field the API does not have would pass every gRPC test
// against the fake and be refused by every cipheron.
//
// It is a copy of the server's walker, not a shared one: the server lives in another module, Go's internal rule
// keeps this module's internal packages from it, and the walker is not public API. The parity test
// (strictfields_test.go) pins its answers.
func strictFields() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		if m, ok := req.(proto.Message); ok {
			if err := unknownFields(m.ProtoReflect()); err != nil {
				return nil, err
			}
		}
		return next(ctx, req)
	}
}

// unknownFields is the refusal of m when it, or any message it holds, carries unknown fields; nil otherwise.
func unknownFields(m protoreflect.Message) error {
	if !m.IsValid() {
		return nil
	}
	if u := m.GetUnknown(); len(u) > 0 {
		name := m.Descriptor().FullName()
		num, _, n := protowire.ConsumeTag(u)
		if n < 0 {
			return status.Errorf(codes.InvalidArgument, "the request carries data in %s that is no field of the API", name)
		}
		return status.Errorf(codes.InvalidArgument, "unknown field %d in %s: the request has a field the API does not have",
			num, name)
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			l := v.List()
			for i := 0; i < l.Len() && err == nil; i++ {
				err = unknownFields(l.Get(i).Message())
			}
		case fd.IsMap() && fd.MapValue().Message() != nil:
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				err = unknownFields(mv.Message())
				return err == nil
			})
		case !fd.IsList() && !fd.IsMap() && fd.Message() != nil:
			err = unknownFields(v.Message())
		}
		return err == nil
	})
	return err
}
