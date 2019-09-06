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
import software.amazon.awssdk.crt.io.TlsContextOptions;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.AlgorithmSpec;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.ExpirationModelType;
import software.amazon.awssdk.services.kms.model.GetParametersForImportRequest;
import software.amazon.awssdk.services.kms.model.GetParametersForImportResponse;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialRequest;
import software.amazon.awssdk.services.kms.model.ImportKeyMaterialResponse;
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionResponse;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;
import software.amazon.awssdk.utils.Logger;

import java.nio.charset.StandardCharsets;
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

        TlsCipherPreference cipherPreferences = null;
        if (TlsContextOptions.isCipherPreferenceSupported(TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06)) {
            LOG.info(() -> "Post-quantum ciphers are supported and will be used!");
            cipherPreferences = TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06;
        } else {
            LOG.warn(() -> "Post-quantum ciphers are not supported, falling back to classic cipher suites.");
            cipherPreferences = TlsCipherPreference.TLS_CIPHER_SYSTEM_DEFAULT;
        }
        try (SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .tlsCipherPreference(cipherPreferences)
                .build();) {
            try (KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
//                                    .region(REGION)
                    .httpClient(awsCrtHttpClient)
//                                    .credentialsProvider(CREDENTIALS_PROVIDER_CHAIN)
                    .build()) {

                // Create an external key
                CreateKeyRequest createRequest = CreateKeyRequest.builder()
                        .origin(OriginType.EXTERNAL)
                        .description("Test key for aws-kms-pq-tls-example")
                        .build();
                CompletableFuture<CreateKeyResponse> createFuture = asyncKMSClient.createKey(createRequest);
                CreateKeyResponse createResponse = createFuture.get();
                String keyId = createResponse.keyMetadata().keyId();
                LOG.info(() -> "Created CMK " + keyId);

                // Get the info needed to import our local key material
                GetParametersForImportRequest getParametersRequest = GetParametersForImportRequest.builder()
                        .keyId(keyId)
                        .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
                        .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                        .build();
                final CompletableFuture<GetParametersForImportResponse> getParametersFuture = asyncKMSClient.getParametersForImport(getParametersRequest);

                // Encrypt our local key to the CMK's public key and import it to KMS
                CompletableFuture<ImportKeyMaterialResponse> importFuture = getParametersFuture.thenCompose(parametersResult -> {
                    final SdkBytes importToken = parametersResult.importToken();
                    final byte[] publicKeyBytes = parametersResult.publicKey().asByteArray();
                    LOG.error(() -> "You should never do this in production! With KMS Import Key you are responsible for keeping a durable copy of the key.");
                    // This key only exists for the lifetime of this lambda and KMS will delete its copy in 600 seconds
                    byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
                    SECURE_RANDOM.nextBytes(plaintextAesKey);
                    LOG.info(() -> String.format("Encrypting AES key [%s] to the CMK %s RSA public key [%s]",
                            ENCODER.encodeToString(plaintextAesKey),
                            keyId,
                            ENCODER.encodeToString(publicKeyBytes)));

                    final RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKeyBytes);
                    final byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);
                    LOG.info(() -> String.format("Encrypted AES key is [%s]",
                            ENCODER.encodeToString(encryptedAesKey)));

                    ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                            .keyId(keyId)
                            .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                            .importToken(importToken)
                            .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                            .validTo(Instant.now().plusSeconds(600))
                            .build();
                    return asyncKMSClient.importKeyMaterial(importRequest);
                });

                CompletableFuture<EncryptResponse> encryptFuture = importFuture.thenCompose(importResult -> {
                    LOG.info(() -> String.format("Encrypting the message [%s]", SECRET_STRING));
                    EncryptRequest encryptRequest = EncryptRequest.builder()
                            .keyId(keyId)
                            .plaintext(SdkBytes.fromString(SECRET_STRING, StandardCharsets.US_ASCII))
                            .build();
                    return asyncKMSClient.encrypt(encryptRequest);
                });

                CompletableFuture<DecryptResponse> decryptFuture = encryptFuture.thenCompose(encryptResult -> {
                    SdkBytes encryptedMessage = encryptResult.ciphertextBlob();
                    LOG.info(() -> "Encrypted message is [%s]" + ENCODER.encodeToString(encryptedMessage.asByteArray()));
                    DecryptRequest decryptRequest = DecryptRequest.builder()
                            .ciphertextBlob(encryptedMessage)
                            .build();
                    return asyncKMSClient.decrypt(decryptRequest);
                });

                CompletableFuture<ScheduleKeyDeletionResponse> deleteFuture = decryptFuture.thenCompose(decryptResult -> {
                    LOG.info(() -> String.format("Decrypted the secret message to [%s]", decryptResult.plaintext().asString(StandardCharsets.US_ASCII)));
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
