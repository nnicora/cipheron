package io.github.nnicora.cipheron;

/** The API a client speaks: the same operations and answers over either. */
public enum Transport {
    /** gRPC over HTTP/2: the default. */
    GRPC,
    /** The JSON API over HTTP/1.1. */
    HTTP
}
