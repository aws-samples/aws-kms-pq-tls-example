/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.example;

import com.example.crypto.RSAUtils;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.crt.io.TlsCipherPreference;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportResponse;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialResponse;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionResponse;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;
import software.amazon.awssdk.utils.Logger;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

public class AwsKmsPqTlsExample {
    private static final Logger LOG = Logger.loggerFor(AwsKmsPqTlsExample.class);
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static Random SECURE_RANDOM = new SecureRandom();
    private static final int AES_KEY_SIZE_BYTES = 256 / 8;
    private static final String SECRET_STRING = "PQ TLS is awesome!";

    public static void main(String[] args) throws Exception {
        LOG.info(() -> "Checking if system supports the hybrid post-quantum cipher suites");
        if (TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06.isSupported()) {
            LOG.info(() -> "Hybrid post-quantum ciphers are supported and will be used");
        } else {
            throw new UnsupportedOperationException("Hybrid post-quantum cipher suites are not supported");
        }
        try (SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .tlsCipherPreference(TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06)
                .build();) {
            // All calls to KMS using asyncKMSClient will use hybrid post-quantum TLS
            try (KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                    .httpClient(awsCrtHttpClient)
                    .build()) {

                // Create a CMK with no key material
                CreateKeyRequest createRequest = CreateKeyRequest.builder()
                        .origin(OriginType.EXTERNAL)
                        .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                        .build();
                CompletableFuture<CreateKeyResponse> createFuture = asyncKMSClient.createKey(createRequest);
                CreateKeyResponse createResponse = createFuture.get();
                String keyId = createResponse.keyMetadata().keyId();
                LOG.info(() -> "Created CMK " + keyId);

                // Get the wrapping key and token required to import the local key material
                GetParametersForImportRequest getParametersRequest = GetParametersForImportRequest.builder()
                        .keyId(keyId)
                        .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
                        .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                        .build();
                final CompletableFuture<GetParametersForImportResponse> getParametersFuture =
                        asyncKMSClient.getParametersForImport(getParametersRequest);

                /*
                 * Creating an in memory AES key. You should never do this in production. With KMS Import Key you are
                 * responsible for keeping a durable copy of the key.
                 * https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
                 *
                 * Use the wrapping key to encrypt the local key material. Then use the token to import the wrapped key
                 * material into KMS.
                 */
                CompletableFuture<ImportKeyMaterialResponse> importFuture = getParametersFuture.thenCompose(parametersResult -> {
                    final SdkBytes importToken = parametersResult.importToken();
                    final byte[] publicKeyBytes = parametersResult.publicKey().asByteArray();

                    // The plaintextAesKey exists only for the lifetime of this function. KMS deletes its plaintext copy
                    // of the key material within 10 minutes (600 seconds).
                    byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
                    SECURE_RANDOM.nextBytes(plaintextAesKey);

                    final RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKeyBytes);
                    final byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);

                    // Import the key material using the CMK ID, wrapped key material, and import token.
                    ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                            .keyId(keyId)
                            .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                            .importToken(importToken)
                            .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                            .validTo(Instant.now().plusSeconds(600))
                            .build();
                    LOG.info(() -> "Importing key material using PQ TLS to protect wrapped AES key in transit to KMS");
                    return asyncKMSClient.importKeyMaterial(importRequest);
                });

                // Use the CMK with imported key material to generate a data key.
                CompletableFuture<GenerateDataKeyResponse> generateDataKeyFuture = importFuture.thenCompose(importResult -> {
                    GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder()
                            .keyId(keyId)
                            .keySpec(DataKeySpec.AES_256)
                            .build();
                    LOG.info(() -> "Generating a data key using PQ TLS to protect the plaintext data key in transit from KMS");
                    return asyncKMSClient.generateDataKey(generateDataKeyRequest);
                });

                // Now decrypt the encrypted data key.
                CompletableFuture<DecryptResponse> decryptFuture = generateDataKeyFuture.thenCompose(generateDataKeyResponse -> {
                    // You can use the plaintext AES key to do client side encryption. You get the plaintext key by
                    // calling generateDataKeyResponse.plaintext()
                    SdkBytes encryptedDataKey = generateDataKeyResponse.ciphertextBlob();
                    DecryptRequest decryptRequest = DecryptRequest.builder()
                            .ciphertextBlob(encryptedDataKey)
                            .build();
                    LOG.info(() -> "Decrypting a KMS ciphertext using PQ TLS to protect the plaintext data in transit from KMS");
                    return asyncKMSClient.decrypt(decryptRequest);
                });

                /*
                 * Schedule deletion of the CMK with imported key material. Because this CMK was created only for this
                 * test, we will delete it as part of cleanup. After the CMK is deleted, any ciphertexts encrypted under
                 * this CMK are permanently unrecoverable.
                 */
                CompletableFuture<ScheduleKeyDeletionResponse> deleteFuture = decryptFuture.thenCompose(decryptResult -> {
                    ScheduleKeyDeletionRequest deletionRequest = ScheduleKeyDeletionRequest.builder()
                            .keyId(keyId)
                            .pendingWindowInDays(7)
                            .build();
                    return asyncKMSClient.scheduleKeyDeletion(deletionRequest);
                });

                ScheduleKeyDeletionResponse deletionResult = deleteFuture.get();
                LOG.info(() -> String.format("CMK %s is schedule to be deleted at %s", keyId, deletionResult.deletionDate()));
            }
        }
    }
}
