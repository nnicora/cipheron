/**
 * cipheron's Java client library. The package {@code io.github.nnicora.cipheron} is its API, and the only package it
 * exports: {@code io.github.nnicora.cipheron.internal.*} (the protocol, the transports, the cryptography) and
 * {@code cipheron.v1} (the API's messages, generated from {@code proto/v1}) are not part of it.
 *
 * <p>gRPC and protobuf ship no module descriptor: they are automatic modules, by the names their jars declare
 * ({@code Automatic-Module-Name}), so javac's warning for requiring one is expected here. One jar declares none,
 * {@code proto-google-common-protos}: its name is derived from its file name.
 */
@SuppressWarnings("requires-automatic")
module io.github.nnicora.cipheron {
    exports io.github.nnicora.cipheron;

    // protobuf reads and builds the generated messages through reflection (their field accessors), for the binary
    // and the JSON form alike.
    opens cipheron.v1 to com.google.protobuf;

    requires jdk.net;

    requires com.google.common; // the generated stub's futures
    requires com.google.gson;
    requires com.google.protobuf;
    requires com.google.protobuf.util;
    requires io.grpc;
    requires io.grpc.netty;
    requires io.grpc.protobuf;
    requires io.grpc.stub;
    requires io.netty.buffer;
    requires io.netty.codec.http;
    requires io.netty.codec.http2;
    requires io.netty.common;
    requires io.netty.handler;
    requires io.netty.transport;
    // google.rpc.Status, ErrorInfo and RetryInfo. The jar declares no module name: this one is its file name's,
    // which a renamed or repackaged jar would change.
    requires proto.google.common.protos;
}
