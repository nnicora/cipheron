package cipherontest

// http.go — the fake's JSON API, the gRPC gateway in front of it as cipheron's listener has it
// (the server): POST only (405 with Allow: POST otherwise), no query string (400), the body bounded as
// cipheron bounds it (transport.HTTPBodyLimit; 413 beyond it, and for a body that decodes to a message beyond
// maxRequestBytes), decoded whole and strictly (an unknown field or anything after the message is 400), the body's
// profile the path's (400 otherwise), exactly two headers forwarded as gRPC metadata (transport.GatewayHeader), none of
// the service's turned into response headers — with cipheron's messages (transport's constants). It shares no code
// with cipheron: the behaviour is held to cipheron's by package cipheron's parity tests.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// HTTPHandler is the JSON API over the fake (the gRPC gateway, as cipheron's own listener serves it), with requests
// bounded by MaxMessageBytes, for a test that serves it on a listener of its own. Like cipheron's, it writes every
// field and enums as NUMBERS (so a signing-key state or tenancy a client does not know reaches it as over gRPC), and
// refuses what cipheron's gateway refuses (the file's comment).
func (s *Server) HTTPHandler(tb testing.TB) http.Handler {
	tb.Helper()
	return s.HTTPHandlerMax(tb, MaxMessageBytes)
}

// HTTPHandlerMax is HTTPHandler for a listener whose requests are at most maxRequestBytes (cipheron's
// maxRequestBytes): the body is bounded by transport.HTTPBodyLimit of it, and the decoded message by it.
func (s *Server) HTTPHandlerMax(tb testing.TB, maxRequestBytes int64) http.Handler {
	tb.Helper()
	var mux *runtime.ServeMux
	mux = runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(transport.GatewayHeader),
		runtime.WithOutgoingHeaderMatcher(func(string) (string, bool) { return "", false }),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &strictJSON{max: maxRequestBytes, JSONPb: &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{EmitUnpopulated: true, UseEnumNumbers: true},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}}),
		runtime.WithErrorHandler(httpError),
		runtime.WithMiddlewares(func(next runtime.HandlerFunc) runtime.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
				if r.URL.RawQuery != "" {
					_, out := runtime.MarshalerForRequest(mux, r)
					runtime.HTTPError(r.Context(), mux, out, w, r, status.Error(codes.InvalidArgument, transport.QueryStringMessage))
					return
				}
				if b, ok := r.Body.(*httpBody); ok {
					b.routed, b.pathProfile = true, pathParams["profile"]
				}
				next(w, r, pathParams)
			}
		}),
	)
	if err := cipheronv1.RegisterCipherServiceHandlerServer(context.Background(), mux, s); err != nil {
		tb.Fatal(err)
	}
	return &httpFront{mux: mux, maxBody: transport.HTTPBodyLimit(maxRequestBytes)}
}

// The fronts' own answers, as cipheron's gateway writes them: a google.rpc.Status in JSON.
var (
	tooLargeBody         = statusBody(status.Error(codes.ResourceExhausted, transport.TooLargeMessage))
	methodNotAllowedBody = statusBody(status.Error(codes.Unimplemented, http.StatusText(http.StatusMethodNotAllowed)))
)

func statusBody(err error) []byte {
	b, merr := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(status.Convert(err).Proto())
	if merr != nil {
		panic(merr)
	}
	return b
}

func writeStatus(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

type httpFront struct {
	mux     *runtime.ServeMux
	maxBody int64
}

func (h *httpFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStatus(w, http.StatusMethodNotAllowed, methodNotAllowedBody)
		return
	}
	if r.ContentLength > h.maxBody {
		w.Header().Set("Connection", "close")
		writeStatus(w, http.StatusRequestEntityTooLarge, tooLargeBody)
		return
	}
	r.Body = &httpBody{ReadCloser: http.MaxBytesReader(w, r.Body, h.maxBody)}
	h.mux.ServeHTTP(w, r)
}

// httpBody is a request body under http.MaxBytesReader that records a request beyond the bound, and carries the
// matched route's {profile} to the decoder.
type httpBody struct {
	io.ReadCloser

	over        bool
	routed      bool
	pathProfile string
}

func (b *httpBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var mbe *http.MaxBytesError
	if err != nil && errors.As(err, &mbe) {
		b.over = true
	}
	return n, err
}

// httpError answers a request beyond the bound 413, every other error as the gateway does.
func httpError(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	if b, ok := r.Body.(*httpBody); ok && b.over {
		writeStatus(w, http.StatusRequestEntityTooLarge, tooLargeBody)
		return
	}
	runtime.DefaultHTTPErrorHandler(ctx, mux, m, w, r, err)
}

// strictJSON decodes the whole body as one request message, strictly, held to max bytes, its profile the path's.
type strictJSON struct {
	*runtime.JSONPb

	max int64
}

func (m *strictJSON) NewDecoder(r io.Reader) runtime.Decoder {
	return runtime.DecoderFunc(func(v any) error {
		msg, ok := v.(proto.Message)
		if !ok {
			return errors.New("the gateway decodes only whole request messages")
		}
		all, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if len(bytes.TrimLeft(all, " \t\r\n")) == 0 {
			return io.EOF
		}
		if err := m.UnmarshalOptions.Unmarshal(all, msg); err != nil {
			return err
		}
		b, _ := r.(*httpBody)
		if int64(proto.Size(msg)) > m.max {
			if b != nil {
				b.over = true
			}
			return errors.New("the request message is larger than the listener's maxRequestBytes")
		}
		if d, ok := msg.(interface{ GetProfile() string }); ok && b != nil && b.routed && d.GetProfile() != "" &&
			d.GetProfile() != b.pathProfile {
			return errors.New(transport.ProfileMismatchMessage)
		}
		return nil
	})
}
