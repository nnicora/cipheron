package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	spb "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/nnicora/cipheron/internal/zeroize"
	"github.com/nnicora/cipheron/peercred"
	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// socketDialer returns the function every connection of a socket client is opened with: it checks the
// listening process's uid (WithServerUID) before the connection is used, and reports the outcome to id.
func socketDialer(abs string, serverUID *uint32, id *identityState) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", abs)
		if serverUID == nil {
			return c, err
		}
		if err != nil {
			id.clear() // nothing listens (yet): not an identity refusal
			return nil, err
		}
		if err := checkServerUID(c, abs, *serverUID); err != nil {
			_ = c.Close()
			if errors.Is(err, errServerHungUp) {
				id.clear() // the listener closed the connection: not an identity refusal (errServerHungUp)
				return nil, err
			}
			id.failed(err)
			return nil, err
		}
		id.clear()
		return c, nil
	}
}

// errServerHungUp is a connection the listening process closed before its credentials were read. It is not an
// identity refusal: Darwin answers ENOTCONN for a peer that is gone (peercred), which says nothing about who
// listens — cipheron itself closes, as it accepts it, a connection from a process no profile lists. The connection
// is discarded unused, like one to a socket nothing listens on, and the next attempt checks the server again.
var errServerHungUp = errors.New("cipheron: the server closed the connection before its credentials were read")

// checkServerUID is WithServerUID's check of one connection. Its refusals are identity errors; a server that hung
// up first is errServerHungUp, which is not.
func checkServerUID(c net.Conn, abs string, want uint32) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return &identityError{errors.New("cipheron: not a unix-socket connection")}
	}
	creds, err := peercred.Of(uc)
	if errors.Is(err, syscall.ENOTCONN) {
		return fmt.Errorf("%w: %s: %w", errServerHungUp, abs, err)
	}
	if err != nil {
		return &identityError{fmt.Errorf("cipheron: the credentials of the process serving %s cannot be read: %w", abs, err)}
	}
	if creds.UID != want {
		return &identityError{fmt.Errorf("cipheron: the process serving %s runs as uid %d, not the expected uid %d: "+
			"refusing to talk to it", abs, creds.UID, want)}
	}
	return nil
}

// tcpDialer opens the TCP connection under a network client's TLS. A connection that cannot be opened is not
// an identity refusal, nor cipheron's refusal of this client's certificate; the TLS handshake on one that is,
// and what is read after it, decide those (watchedCreds).
func tcpDialer(id *identityState, deny *refusals) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			id.clear()
			deny.clear()
		}
		return c, err
	}
}

// DialGRPC returns a client that speaks gRPC to cipheron at where: a unix socket (a path, or unix:///path, with
// WithServerUID or WithAnyServer) or the network listener (host:port, with WithTLS or WithTLSFiles and a request
// key) — or, with WithEnvironment and where "", the socket and options the cipheron-sidecar chart's environment
// names. It keeps WithConnections connections (default DefaultConnections) and takes them in turn. A connection
// is made lazily, by the first call that needs it, and a call waits for it until the call's context ends (gRPC's
// wait-for-ready): a sidecar that is still unsealing, or restarting, delays a call instead of failing it. A
// server WithServerUID or the TLS verification refuses does not: the calls waiting fail with ErrServerIdentity
// as soon as the connection is refused, and later calls fail at once until a connection succeeds. Nor does
// cipheron refusing this client's certificate on the network (a SPIFFE ID no profile lists, ...): told so by an
// authenticated TLS alert, the calls waiting on that connection fail with PERMISSION_DENIED, and a later call
// asks for a fresh connection attempt at once and fails only if that one is refused too (refusal.go).
//
// On the socket the connection has no TLS ("insecure" is gRPC's name for that): the socket is local, the
// payloads on it are HPKE-sealed, and cipheron authorizes by this process's kernel credentials. On the network
// it is mutual TLS, and the payloads are HPKE-sealed inside it all the same.
//
// The connections' parameters are fixed here (the constants below): how long gRPC waits between two attempts to
// connect at most (socketMaxBackoff, networkMaxBackoff — not gRPC's two minutes, so a cipheron that comes back is
// found soon), a keepalive on the network (a connection whose peer vanished is noticed, and its calls fail
// UNAVAILABLE, instead of hanging until their deadlines), and the same fixed flow-control windows cipheron's
// listener uses.
func DialGRPC(where string, opts ...Option) (*Client, error) {
	p, err := resolve(where, opts)
	if err != nil {
		return nil, err
	}
	id := newIdentityState()
	common := []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.WaitForReady(true),
		grpc.MaxCallRecvMsgSize(p.maxMessage), grpc.MaxCallSendMsgSize(p.maxMessage)),
		// Fixed windows, cipheron's own (its listener's grpcStreamWindow and grpcConnWindow): setting them turns
		// off gRPC's estimation of the windows from the traffic, so what one connection may buffer of an answer is
		// known, and a default-sized answer moves in one window.
		grpc.WithInitialWindowSize(grpcStreamWindow), grpc.WithInitialConnWindowSize(grpcConnWindow),
		// Every call declares its message's size (cipheron's memory budget admits it by that size).
		grpc.WithChainUnaryInterceptor(declareRequestBytes)}
	target := p.address
	if p.socket != "" {
		dial := socketDialer(p.socket, p.serverUID, id)
		target = unixScheme + p.socket
		common = append(common, grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dial(ctx) }),
			grpc.WithConnectParams(connectParams(socketMaxBackoff, socketConnectTimeout)))
	} else {
		common = append(common, grpc.WithConnectParams(connectParams(networkMaxBackoff, networkConnectTimeout)),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: keepaliveTime, Timeout: keepaliveTimeout,
				PermitWithoutStream: false}))
		if p.roundRobin {
			// WithRoundRobin: gRPC's DNS resolver over the host, round_robin over what it resolves. The authority
			// (the server name TLS verifies) is still the address's host.
			var extra []grpc.DialOption
			target, extra = roundRobinTarget(p.address)
			common = append(common, extra...)
			common = append(common, grpc.WithDefaultServiceConfig(roundRobinServiceConfig))
		}
	}
	n := p.connections
	if n == 0 {
		n = DefaultConnections
	}
	rpcs := make([]rpc, 0, n)
	for range n {
		opts := common
		var deny *refusals
		if p.socket == "" {
			// Each connection of the pool has its own record of refusals: one connection refused ends the
			// calls waiting on it, not those on the others (which may reach another replica).
			deny = newRefusals()
			opts = append(slices.Clip(common), grpc.WithTransportCredentials(watchedCreds{credentials.NewTLS(p.tls), id, deny}),
				grpc.WithContextDialer(tcpDialer(id, deny)))
		}
		conn, err := grpc.NewClient(target, opts...)
		if err != nil {
			for _, r := range rpcs {
				_ = r.Close()
			}
			zeroize.Bytes(p.requestKey) // this client's copy, which no Close will wipe
			return nil, fmt.Errorf("cipheron: %w", err)
		}
		rpcs = append(rpcs, &grpcRPC{conn: conn, c: cipheronv1.NewCipherServiceClient(conn), id: id, deny: deny})
	}
	return newClient(rpcs, id, p), nil
}

// declareRequestBytes is the gRPC connections' unary interceptor: it declares the size of every call's request message
// — its protobuf encoding, what gRPC sends — in the outgoing metadata transport.RequestBytesMetadataKey, replacing any
// value the caller's context put there: cipheron reserves the memory the request needs before it reads it, and admits
// a request beyond its listener's undeclaredMaxRequestBytes only so. An empty message declares 1 byte (0 is no size).
func declareRequestBytes(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
) error {
	if m, ok := req.(proto.Message); ok {
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(transport.RequestBytesMetadataKey, strconv.Itoa(max(1, proto.Size(m))))
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

// The gRPC connections' parameters (DialGRPC).
const (
	// socketMaxBackoff and networkMaxBackoff are the longest gRPC waits between two attempts to connect (its
	// default is two minutes). A sidecar restarts in seconds and an attempt on a unix socket costs nothing, so a
	// call waiting for it should find it within a couple of seconds; on the network an attempt is a TCP and a TLS
	// handshake against a server that may be struggling, so the cap is moderate.
	socketMaxBackoff  = 2 * time.Second
	networkMaxBackoff = 10 * time.Second
	// socketConnectTimeout and networkConnectTimeout are what one attempt is given at least (gRPC's
	// MinConnectTimeout; its default is 20 s): on the network the TCP and TLS handshakes, on the socket a connect
	// and the peer-credential check.
	socketConnectTimeout  = 5 * time.Second
	networkConnectTimeout = 20 * time.Second
	// keepaliveTime is how long a network connection with a call on it may be silent before the client pings it,
	// and keepaliveTimeout how long the ping may go unanswered before the connection is closed (its calls then
	// fail UNAVAILABLE). cipheron's listener sends GOAWAY (too_many_pings) to a client that pings more often than
	// every 20 s (the server's keepaliveMinTime): 30 s keeps clear of it. No ping without a call
	// (PermitWithoutStream false): an idle connection is cipheron's to close (its idle timeout), and gRPC connects
	// again at the next call.
	keepaliveTime    = 30 * time.Second
	keepaliveTimeout = 15 * time.Second
	// grpcStreamWindow and grpcConnWindow are the flow-control windows of a connection, the values cipheron's
	// listener sets for its side (the server): 1 MiB a stream, 4 MiB a connection.
	grpcStreamWindow = 1 << 20
	grpcConnWindow   = 4 << 20
)

// roundRobinServiceConfig is the service configuration WithRoundRobin sets: gRPC's round_robin policy (registered by
// the grpc package itself).
const roundRobinServiceConfig = `{"loadBalancingConfig":[{"round_robin":{}}]}`

// roundRobinTarget is the gRPC target of a WithRoundRobin client for address (host:port), and any dial option it
// needs: the DNS resolver. A variable so that a test can resolve a name to several loopback servers.
var roundRobinTarget = func(address string) (string, []grpc.DialOption) {
	return "dns:///" + address, nil
}

// connectParams is gRPC's default connection backoff (1 s, growing by 1.6, jittered) capped at maxDelay, with at
// least minConnect for one attempt.
func connectParams(maxDelay, minConnect time.Duration) grpc.ConnectParams {
	b := backoff.DefaultConfig
	b.MaxDelay = maxDelay
	return grpc.ConnectParams{Backoff: b, MinConnectTimeout: minConnect}
}

type grpcRPC struct {
	conn *grpc.ClientConn
	c    cipheronv1.CipherServiceClient
	id   *identityState
	deny *refusals // nil on the socket
}

// state is the connection's gRPC state (Client.pick).
func (g *grpcRPC) state() connectivity.State { return g.conn.GetState() }

// begin registers a call with the identity state and the connection's refusals: the context the call runs with
// (ended by either's refusal), its call options, and done. When the connection's last attempt was refused for
// this client's certificate, the call asks gRPC for a fresh attempt now rather than after its backoff (hurry):
// it waits for that attempt's outcome, not for a backoff that grew while the client was refused.
func (g *grpcRPC) begin(ctx context.Context) (context.Context, []grpc.CallOption, func()) {
	ctx, _ = withRequestID(ctx) // the call's x-request-id (requestid.go); outcome reads it back for the error
	cctx, opts, done := g.id.begin(ctx)
	if g.deny == nil {
		return cctx, opts, done
	}
	dctx, refused, since, ddone := g.deny.beginAt(cctx)
	if refused {
		go hurry(dctx, g.conn, g.deny, since)
	}
	return dctx, opts, func() { ddone(); done() }
}

// hurryInterval is how often a call waiting after a refusal cuts gRPC's connection backoff short.
const hurryInterval = 50 * time.Millisecond

// backoffConn is what hurry needs of a grpc.ClientConn.
type backoffConn interface {
	GetState() connectivity.State
	ResetConnectBackoff()
}

// hurry cuts the connection's backoff short until ONE connection attempt has had its outcome since the call began
// (since: refusals.beginAt), the connection is ready, or the call ends — whichever comes first. Once is not
// enough: a refusal is read, and ends the calls waiting, before gRPC has put the connection in backoff, and a
// reset that lands before the backoff starts is lost; so it repeats, every hurryInterval. But only until that one
// attempt: its outcome is either another refusal, which ends the call, or anything else (the server is not
// reachable, or the handshake completed) — and then the call waits as every call does, at gRPC's own pace. A call
// with a long deadline against a server that is down must not turn into an attempt every hurryInterval for as long
// as it waits.
func hurry(ctx context.Context, conn backoffConn, deny *refusals, since uint64) {
	t := time.NewTicker(hurryInterval)
	defer t.Stop()
	for {
		if conn.GetState() == connectivity.Ready || deny.settled(since) {
			return
		}
		conn.ResetConnectBackoff()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (g *grpcRPC) PublicKey(ctx context.Context, r *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.PublicKey(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) Encrypt(ctx context.Context, r *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.Encrypt(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) Decrypt(ctx context.Context, r *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.Decrypt(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) Sign(ctx context.Context, r *cipheronv1.SignRequest) (*cipheronv1.SignResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.Sign(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) CreateTenantKey(ctx context.Context, r *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.CreateTenantKey(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) ReEncrypt(ctx context.Context, r *cipheronv1.ReEncryptRequest) (*cipheronv1.ReEncryptResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.ReEncrypt(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) RewrapTenantKey(ctx context.Context, r *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.RewrapTenantKey(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) EncryptBatch(ctx context.Context, r *cipheronv1.EncryptBatchRequest) (*cipheronv1.EncryptBatchResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.EncryptBatch(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) DecryptBatch(ctx context.Context, r *cipheronv1.DecryptBatchRequest) (*cipheronv1.DecryptBatchResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.DecryptBatch(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) ReEncryptBatch(ctx context.Context, r *cipheronv1.ReEncryptBatchRequest) (*cipheronv1.ReEncryptBatchResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.ReEncryptBatch(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) RewrapTenantKeyBatch(ctx context.Context, r *cipheronv1.RewrapTenantKeyBatchRequest) (*cipheronv1.RewrapTenantKeyBatchResponse, error) {
	cctx, opts, done := g.begin(ctx)
	defer done()
	resp, err := g.c.RewrapTenantKeyBatch(cctx, r, opts...)
	return resp, outcome(cctx, err)
}

func (g *grpcRPC) Close() error { return g.conn.Close() }

// The HTTP transport's connection pool (DialHTTP).
const (
	// httpIdleTimeout is how long an idle connection is kept: under cipheron's own two minutes (its listener
	// closes a connection idle that long, the server's idleTimeout), so the client drops a connection
	// before cipheron does and a request is not written into one cipheron is closing.
	httpIdleTimeout = 90 * time.Second
)

// httpTransport is the http.Transport of an HTTP client keeping at most connections connections to cipheron
// (WithConnections, at most MaxConnections — under cipheron's default of 32 per caller, maxConnectionsPerCaller),
// idle ones included: a burst of calls waits for one of them instead of opening a connection each, which
// cipheron's cap per caller would refuse. No proxy from the environment, no compression, no HTTP/2.
func httpTransport(connections int) *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        connections,
		MaxIdleConnsPerHost: connections,
		MaxConnsPerHost:     connections,
		IdleConnTimeout:     httpIdleTimeout,
		// HTTP/1.1 only: a non-nil, empty TLSNextProto keeps the transport from upgrading to HTTP/2, which on
		// cipheron's network listener is the gRPC server (it answers a JSON request 415).
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}

// noRedirect is the HTTP client's CheckRedirect: no redirect is followed, and the 3xx answer is handed to call.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newHTTPRPC is the HTTP transport's rpc over tr, to base. It never follows a redirect: cipheron answers none,
// and following one would send the request — its sealed payload and its request signature — again, to wherever a
// party that answered in cipheron's place names: on the network, outside the TLS configuration that authenticated
// the server (to plain http, or to a host the address did not name). The 3xx answer is the call's error (call).
func newHTTPRPC(tr *http.Transport, base string, limit int64) *httpRPC {
	return &httpRPC{client: &http.Client{Transport: tr, CheckRedirect: noRedirect}, tr: tr, base: base, limit: limit}
}

// DialHTTP returns a client that speaks cipheron's HTTP API (POST /v1/cipher/{profile}/{operation}, JSON
// bodies) to where: over the unix socket, or over HTTPS with mutual TLS to the network listener. The JSON API
// is HTTP/1.1 only — on the network listener ALPN h2 is cipheron's gRPC server, which a JSON request does not
// reach — so the client offers http/1.1 alone. Addresses and options as DialGRPC's; a refused server fails the
// call with ErrServerIdentity, and cipheron refusing this client's certificate (an authenticated TLS alert,
// refusal.go) with PERMISSION_DENIED. Every other failure to connect is UNAVAILABLE, at once: this transport
// does not wait for a connection.
//
// It keeps at most WithConnections connections (default DefaultHTTPConnections), idle ones included, and an HTTP/1.1
// connection carries one request at a time: that many calls run at once and the others wait for a connection,
// until their contexts end. An idle connection is closed after httpIdleTimeout, before cipheron closes it. A
// redirect is never followed (FAILED_PRECONDITION: what answered is not cipheron's API), and the request is never
// sent a second time; an HTTP 404 of an operation's route is UNIMPLEMENTED (a cipheron without the operation).
func DialHTTP(where string, opts ...Option) (*Client, error) {
	p, err := resolve(where, opts)
	if err != nil {
		return nil, err
	}
	if p.roundRobin {
		zeroize.Bytes(p.requestKey) // this client's copy, which no Close will wipe
		return nil, errors.New("cipheron: WithRoundRobin is gRPC's (DialGRPC): the HTTP client keeps one transport, " +
			"which does not spread its connections over resolved addresses")
	}
	id := newIdentityState()
	// A JSON body carries bytes in base64: 4 characters for every 3 bytes, and some framing.
	limit := int64(p.maxMessage)/3*4 + 64<<10
	n := p.connections
	if n == 0 {
		n = DefaultHTTPConnections
	}
	tr := httpTransport(n)
	if p.socket != "" {
		dial := socketDialer(p.socket, p.serverUID, id)
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
		// The host is not dialled (DialContext ignores it); it only has to be a valid one.
		return newClient([]rpc{newHTTPRPC(tr, "http://cipheron", limit)}, id, p), nil
	}
	tc := p.tls.Clone()
	tc.NextProtos = []string{"http/1.1"}
	// The handshake is made here, not by the transport, so the connection can watch for cipheron's refusal of
	// this client's certificate, which TLS 1.3 delivers after the handshake (refusal.go).
	tr.DialTLSContext = tlsDialer(tc)
	// Nothing of this client is ever sent in plaintext TCP: a request that is not https has no connection.
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("cipheron: a network client speaks TLS only")
	}
	return newClient([]rpc{newHTTPRPC(tr, "https://"+p.address, limit)}, id, p), nil
}

// tlsDialer opens a TLS connection with cfg as net/http would with it as TLSClientConfig — the server name is
// the address's host unless cfg names one — and watches it for a certificate refusal (watchRefusals). Every
// call opens or reuses its own connection, so a refusal fails the call that read it: nothing to report.
func tlsDialer(cfg *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		c := cfg
		if c.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			c = cfg.Clone()
			c.ServerName = host
		}
		tc := tls.Client(raw, c)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return watchRefusals(tc, tc.ConnectionState(), nil), nil
	}
}

type httpRPC struct {
	client *http.Client
	tr     *http.Transport
	base   string // scheme and authority of every request URL
	limit  int64  // the largest response body read
	closed atomic.Bool
}

func (h *httpRPC) PublicKey(ctx context.Context, r *cipheronv1.PublicKeyRequest) (*cipheronv1.PublicKeyResponse, error) {
	out := &cipheronv1.PublicKeyResponse{}
	return out, h.call(ctx, r.GetProfile(), "public-key", r, out)
}

func (h *httpRPC) Encrypt(ctx context.Context, r *cipheronv1.EncryptRequest) (*cipheronv1.EncryptResponse, error) {
	out := &cipheronv1.EncryptResponse{}
	return out, h.call(ctx, r.GetProfile(), "encrypt", r, out)
}

func (h *httpRPC) Decrypt(ctx context.Context, r *cipheronv1.DecryptRequest) (*cipheronv1.DecryptResponse, error) {
	out := &cipheronv1.DecryptResponse{}
	return out, h.call(ctx, r.GetProfile(), "decrypt", r, out)
}

func (h *httpRPC) Sign(ctx context.Context, r *cipheronv1.SignRequest) (*cipheronv1.SignResponse, error) {
	out := &cipheronv1.SignResponse{}
	return out, h.call(ctx, r.GetProfile(), "sign", r, out)
}

func (h *httpRPC) CreateTenantKey(ctx context.Context, r *cipheronv1.CreateTenantKeyRequest) (*cipheronv1.CreateTenantKeyResponse, error) {
	out := &cipheronv1.CreateTenantKeyResponse{}
	return out, h.call(ctx, r.GetProfile(), "tenant-key", r, out)
}

func (h *httpRPC) ReEncrypt(ctx context.Context, r *cipheronv1.ReEncryptRequest) (*cipheronv1.ReEncryptResponse, error) {
	out := &cipheronv1.ReEncryptResponse{}
	return out, h.call(ctx, r.GetProfile(), "reencrypt", r, out)
}

func (h *httpRPC) RewrapTenantKey(ctx context.Context, r *cipheronv1.RewrapTenantKeyRequest) (*cipheronv1.RewrapTenantKeyResponse, error) {
	out := &cipheronv1.RewrapTenantKeyResponse{}
	return out, h.call(ctx, r.GetProfile(), "rewrap-tenant-key", r, out)
}

func (h *httpRPC) EncryptBatch(ctx context.Context, r *cipheronv1.EncryptBatchRequest) (*cipheronv1.EncryptBatchResponse, error) {
	out := &cipheronv1.EncryptBatchResponse{}
	return out, h.call(ctx, r.GetProfile(), "encrypt-batch", r, out)
}

func (h *httpRPC) DecryptBatch(ctx context.Context, r *cipheronv1.DecryptBatchRequest) (*cipheronv1.DecryptBatchResponse, error) {
	out := &cipheronv1.DecryptBatchResponse{}
	return out, h.call(ctx, r.GetProfile(), "decrypt-batch", r, out)
}

func (h *httpRPC) ReEncryptBatch(ctx context.Context, r *cipheronv1.ReEncryptBatchRequest) (*cipheronv1.ReEncryptBatchResponse, error) {
	out := &cipheronv1.ReEncryptBatchResponse{}
	return out, h.call(ctx, r.GetProfile(), "reencrypt-batch", r, out)
}

func (h *httpRPC) RewrapTenantKeyBatch(ctx context.Context, r *cipheronv1.RewrapTenantKeyBatchRequest) (*cipheronv1.RewrapTenantKeyBatchResponse, error) {
	out := &cipheronv1.RewrapTenantKeyBatchResponse{}
	return out, h.call(ctx, r.GetProfile(), "rewrap-tenant-key-batch", r, out)
}

// Close ends the transport's use: no request is sent afterwards (call), and the idle connections are closed. A
// request already written is answered as it would have been.
func (h *httpRPC) Close() error {
	h.closed.Store(true)
	h.tr.CloseIdleConnections()
	return nil
}

// call POSTs req as JSON to the operation's path and decodes the answer into resp. An error answer becomes
// the gRPC status the gateway wrote, so both transports fail alike.
func (h *httpRPC) call(ctx context.Context, profile, op string, req, resp proto.Message) error {
	ctx, id := withRequestID(ctx)
	return withID(h.callOnce(ctx, id, profile, op, req, resp), id)
}

// callOnce is call with the request id id sent as the X-Request-Id header.
func (h *httpRPC) callOnce(ctx context.Context, id, profile, op string, req, resp proto.Message) error {
	if h.closed.Load() {
		return ErrClosed
	}
	body, err := protojson.Marshal(req)
	if err != nil {
		return err
	}
	u := h.base + "/v1/cipher/" + url.PathEscape(profile) + "/" + op
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(transport.HTTPRequestIDHeader, id)
	res, err := h.client.Do(hr)
	if err != nil {
		if isIdentityError(err) {
			return identityFailure(err)
		}
		var r *authenticatedRefusalError
		if errors.As(err, &r) {
			return &refusedError{err: r.err}
		}
		return status.Error(codes.Unavailable, err.Error())
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := transport.ReadHTTPBody(res.Body, res.ContentLength, h.limit) // sized once from Content-Length
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	if int64(len(raw)) > h.limit {
		return fmt.Errorf("%w: the answer is larger than %d bytes (WithMaxMessageBytes)", ErrTooLarge, h.limit)
	}
	switch {
	case res.StatusCode >= 300 && res.StatusCode < 400:
		// Not followed (noRedirect), and the request was sent once, to the address this client was given.
		return status.Errorf(codes.FailedPrecondition, "cipheron answered HTTP %d, a redirect (to %s): cipheron never "+
			"redirects, so what answered at this address is not cipheron's API; the redirect was not followed and the "+
			"request was not sent again", res.StatusCode, redirectTarget(res))
	case res.StatusCode == http.StatusNotFound:
		// The gateway's answer for a path it has no route for: an operation the server does not have, as gRPC
		// answers UNIMPLEMENTED for a method it does not know. cipheron answers no 404 of its own: a profile it does
		// not know, or does not let this caller use, is PERMISSION_DENIED (403).
		return status.Errorf(codes.Unimplemented, "cipheron answered HTTP 404 for the %s operation's route: the "+
			"server does not serve it", op)
	case res.StatusCode != http.StatusOK:
		return httpStatus(res.StatusCode, raw)
	}
	// An unknown field is dropped: this client never reads a field it does not have, and every field it reads is
	// covered by the answer's signature. An enum written as a NUMBER — as cipheron writes them — is kept whatever the
	// number, as gRPC keeps it: a signing-key state that is none of the three refuses the whole answer (client.go,
	// fetchKeys). An unknown enum NAME would be dropped, reading as 0, which refuses the answer too: fail-closed.
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, resp)
}

// redirectTarget is a redirect answer's Location for an error message: quoted, and no longer than a line.
func redirectTarget(res *http.Response) string {
	loc := res.Header.Get("Location")
	if loc == "" {
		return "no Location"
	}
	const most = 200
	if len(loc) > most {
		loc = loc[:most] + "…"
	}
	return fmt.Sprintf("%q", loc)
}

// tooLargeError is an HTTP 413: ErrTooLarge, and RESOURCE_EXHAUSTED for a caller that reads codes — the two
// things gRPC's own size refusal is once package cipheron mapped it.
type tooLargeError struct{ msg string }

func (e *tooLargeError) Error() string        { return ErrTooLarge.Error() + ": " + e.msg }
func (e *tooLargeError) Is(target error) bool { return target == ErrTooLarge }
func (e *tooLargeError) GRPCStatus() *status.Status {
	return status.New(codes.ResourceExhausted, e.Error())
}

// busy is an HTTP 429 whose body told nothing more: RESOURCE_EXHAUSTED with a RetryInfo of a second, the delay
// cipheron's own busy answer carries — which is what makes it "busy, retry later" (package cipheron: ErrBusy) and not a
// size refusal.
func busy(msg string) error {
	st, err := status.New(codes.ResourceExhausted, msg).WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(time.Second)})
	if err != nil {
		return status.Error(codes.Unavailable, msg) // a constant detail of a registered type: cannot fail
	}
	return st.Err()
}

// httpStatus reads the gateway's error body — a google.rpc.Status in JSON, {"code": n, "message": "...",
// "details": [...]} — into a gRPC status, its details (cipheron's ErrorInfo and RetryInfo) included.
//
// Two HTTP statuses are decided by the HTTP status itself, whatever the body, because a RESOURCE_EXHAUSTED status
// alone does not tell them apart and the body's details can be lost — the body is not a status at all (something
// else answered), or its details are of a type this build does not know, which protojson refuses whole:
//   - 413 is a size refusal: ErrTooLarge (tooLargeError), as gRPC's own refusal of a message over the limit is to
//     package cipheron;
//   - 429 is "busy, retry later": the body's status when it was read (whatever details it has: a
//     RESOURCE_EXHAUSTED without any is then what it is over gRPC, and package cipheron's ErrUnavailable), and when it
//     could not be read RESOURCE_EXHAUSTED with a RetryInfo (busy) — the lost details are not allowed to turn
//     cipheron's busy answer into a bare RESOURCE_EXHAUSTED.
//
// Every other status is the body's status when it has one (its code and message, when the details could not be
// read), and the HTTP status's nearest code otherwise.
func httpStatus(httpCode int, raw []byte) error {
	var st spb.Status
	full := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &st) == nil && st.GetCode() != 0
	var body struct {
		Code    int32  `json:"code"`
		Message string `json:"message"`
	}
	msg := fmt.Sprintf("cipheron answered HTTP %d", httpCode)
	parsed := json.Unmarshal(raw, &body) == nil && body.Code != 0
	if parsed && body.Message != "" {
		msg = body.Message
	}
	switch {
	case httpCode == http.StatusRequestEntityTooLarge:
		return &tooLargeError{msg: msg}
	case httpCode == http.StatusTooManyRequests && !full:
		return busy(msg)
	case full:
		return status.FromProto(&st).Err()
	case parsed:
		return status.Error(codes.Code(body.Code), body.Message)
	}
	code := codes.Unknown
	switch httpCode {
	case http.StatusBadRequest:
		code = codes.InvalidArgument
	case http.StatusForbidden:
		code = codes.PermissionDenied
	case http.StatusServiceUnavailable:
		code = codes.Unavailable
	case http.StatusNotImplemented, http.StatusMethodNotAllowed:
		code = codes.Unimplemented
	}
	return status.Error(code, msg)
}
