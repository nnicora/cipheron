package io.github.nnicora.cipheron.internal.client;

import cipheron.v1.CipherServiceGrpc;
import cipheron.v1.Cipheron;
import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;

/**
 * One RPC of {@code cipheron.v1.CipherService}: its gRPC method, its JSON route ({@code POST
 * /v1/cipher/{profile}/<route>}) and its answer's type.
 *
 * @param method the gRPC method
 * @param route the last segment of the JSON route
 * @param response an empty answer, to parse JSON answers into
 * @param <Q> the request's type
 * @param <R> the answer's type
 */
public record Op<Q extends Message, R extends Message>(MethodDescriptor<Q, R> method, String route, R response) {
    public static final Op<Cipheron.PublicKeyRequest, Cipheron.PublicKeyResponse> PUBLIC_KEY = new Op<>(
            CipherServiceGrpc.getPublicKeyMethod(), "public-key", Cipheron.PublicKeyResponse.getDefaultInstance());
    public static final Op<Cipheron.EncryptRequest, Cipheron.EncryptResponse> ENCRYPT = new Op<>(
            CipherServiceGrpc.getEncryptMethod(), "encrypt", Cipheron.EncryptResponse.getDefaultInstance());
    public static final Op<Cipheron.DecryptRequest, Cipheron.DecryptResponse> DECRYPT = new Op<>(
            CipherServiceGrpc.getDecryptMethod(), "decrypt", Cipheron.DecryptResponse.getDefaultInstance());
    public static final Op<Cipheron.SignRequest, Cipheron.SignResponse> SIGN = new Op<>(
            CipherServiceGrpc.getSignMethod(), "sign", Cipheron.SignResponse.getDefaultInstance());
    public static final Op<Cipheron.ReEncryptRequest, Cipheron.ReEncryptResponse> RE_ENCRYPT = new Op<>(
            CipherServiceGrpc.getReEncryptMethod(), "reencrypt", Cipheron.ReEncryptResponse.getDefaultInstance());
    public static final Op<Cipheron.CreateTenantKeyRequest, Cipheron.CreateTenantKeyResponse> CREATE_TENANT_KEY =
            new Op<>(CipherServiceGrpc.getCreateTenantKeyMethod(), "tenant-key",
                    Cipheron.CreateTenantKeyResponse.getDefaultInstance());
    public static final Op<Cipheron.RewrapTenantKeyRequest, Cipheron.RewrapTenantKeyResponse> REWRAP_TENANT_KEY =
            new Op<>(CipherServiceGrpc.getRewrapTenantKeyMethod(), "rewrap-tenant-key",
                    Cipheron.RewrapTenantKeyResponse.getDefaultInstance());
    public static final Op<Cipheron.EncryptBatchRequest, Cipheron.EncryptBatchResponse> ENCRYPT_BATCH = new Op<>(
            CipherServiceGrpc.getEncryptBatchMethod(), "encrypt-batch",
            Cipheron.EncryptBatchResponse.getDefaultInstance());
    public static final Op<Cipheron.DecryptBatchRequest, Cipheron.DecryptBatchResponse> DECRYPT_BATCH = new Op<>(
            CipherServiceGrpc.getDecryptBatchMethod(), "decrypt-batch",
            Cipheron.DecryptBatchResponse.getDefaultInstance());
    public static final Op<Cipheron.ReEncryptBatchRequest, Cipheron.ReEncryptBatchResponse> RE_ENCRYPT_BATCH =
            new Op<>(CipherServiceGrpc.getReEncryptBatchMethod(), "reencrypt-batch",
                    Cipheron.ReEncryptBatchResponse.getDefaultInstance());
    public static final Op<Cipheron.RewrapTenantKeyBatchRequest, Cipheron.RewrapTenantKeyBatchResponse>
            REWRAP_TENANT_KEY_BATCH = new Op<>(CipherServiceGrpc.getRewrapTenantKeyBatchMethod(),
                    "rewrap-tenant-key-batch", Cipheron.RewrapTenantKeyBatchResponse.getDefaultInstance());
}
