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
import software.amazon.awssdk.services.kms.model.OriginType;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionResponse;
import software.amazon.awssdk.services.kms.model.WrappingKeySpec;
import software.amazon.awssdk.utils.Logger;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

/*
 * This Java code shows how to configure AWS Java SDK 2.0 with the AWS Common Runtime (AWS CRT) HTTP client. Then, it
 * uses the KMS client to import a key, generate a data key, and decrypt the encrypted data key.
 */
public class AwsKmsPqTlsExample {
    private static final Logger LOG = Logger.loggerFor(AwsKmsPqTlsExample.class);
    private static Random SECURE_RANDOM = new SecureRandom();
    private static final int AES_KEY_SIZE_BYTES = 256 / 8;

    public static void main(String[] args) throws Exception {
        /*
         * Check preconditions before continuing. The AWS CRT supports hybrid post-quantum TLS on Linux systems only.
         */
        if (TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06.isSupported()) {
            LOG.info(() -> "Hybrid post-quantum ciphers are supported and will be used");
        } else {
            throw new UnsupportedOperationException("Hybrid post-quantum cipher suites are only supported on Linux systems");
        }

        /*
         * Setup the HTTP client and SDK for use in the rest of the demo. We've already checked that the
         * TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06 cipher suite is supported, if you attempt to use it on an unsupported
         * platform you will encounter a runtime exception.
         */
        SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .tlsCipherPreference(TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06)
                .build();
        // All calls to KMS using asyncKMSClient will use hybrid post-quantum TLS
        KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                .httpClient(awsCrtHttpClient)
                .build();


        /*
         * Import key workflow with hybrid post-quantum TLS
         *
         * Step 1: Create a CMK with no key material
         */
        CreateKeyRequest createRequest = CreateKeyRequest.builder()
                .origin(OriginType.EXTERNAL)
                .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                .build();
        CompletableFuture<CreateKeyResponse> createFuture = asyncKMSClient.createKey(createRequest);
        CreateKeyResponse createResponse = createFuture.get();
        String keyId = createResponse.keyMetadata().keyId();
        LOG.info(() -> "Created CMK " + keyId);

        /*
         * Step 2: Get the wrapping key and token required to import the local key material. The AlgorithmSpec dictates
         * how we must wrap the local key using the public key from KMS.
         */
        GetParametersForImportRequest getParametersRequest = GetParametersForImportRequest.builder()
                .keyId(keyId)
                .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
                .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                .build();
        GetParametersForImportResponse getParametersResponse =
                asyncKMSClient.getParametersForImport(getParametersRequest).get();

        /*
         * Step 3: Prepare the parameters for the ImportKeyMaterial call.
         */
        SdkBytes importToken = getParametersResponse.importToken();
        byte[] publicKeyBytes = getParametersResponse.publicKey().asByteArray();

        /*
         * Create an in memory AES key. You should never do this in production. With KMS Import Key you are
         * responsible for keeping a durable copy of the key.
         * https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
         *
         * The plaintextAesKey exists only for the lifetime of this function. KMS will delete its plaintext copy
         * of the key material within 10 minutes, this is the 'validTo(Instant.now().plusSeconds(600))' in the
         * ImportKeyMaterial call below.
         */
        byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(plaintextAesKey);

        /*
         * Use the wrapping key to encrypt the local key material. Then use the token to import the wrapped key
         * material into KMS. A large scale quantum computer would be able to decrypt the RSA wrapped key and
         */
        RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKeyBytes);
        byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);

        /*
         * Step 4: Import the key material using the CMK ID, wrapped key material, and import token. This is the
         * important call to protect. Your local AES key is leaving your computer and sent over the network wrapped by
         * a RSA public key and encrypted with the TLS connection.
         *
         * This AES key will be used for all KMS Crypto operations when you use this CMK. If this key is compromised all
         * ciphertexts from KMS are also compromised.
         */
        ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                .keyId(keyId)
                .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                .importToken(importToken)
                .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                .validTo(Instant.now().plusSeconds(600))
                .build();
        LOG.info(() -> String.format("Importing key material into CMK %s using PQ TLS to protect wrapped AES key in" +
                "transit to KMS", keyId));
        asyncKMSClient.importKeyMaterial(importRequest).get();

        /*
         * Sensitive cryptography operations workflow. Use a KMS CMK to encrypt and decrypt data. This could be any type
         * of CMK (AWS_KMS, EXTERNAL, or AWS_CLOUDHSM). This will reuse the above EXTERNAL CMK.
         *
         * Step 1: Generate a data key, KMS GenerateDataKey returns the plaintext AES key and an encrypted copy that is
         * encrypted with the CMK. It is our responsibility to keep the ciphertext so the plaintext data key can be
         * retrieved in the future.
         */
        GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(DataKeySpec.AES_256)
                .build();
        LOG.info(() -> String.format("Generating a data key using PQ TLS to protect the plaintext data key in transit " +
                "from KMS. The encrypted data key is encrypted with CMK %s", keyId));
        GenerateDataKeyResponse generateDataKeyResponse = asyncKMSClient.generateDataKey(generateDataKeyRequest).get();

        /*
         * Step 2: Use the plaintext data key for client side encryption. You can get the plaintext data key by calling
         * generateDataKeyResponse.plaintext(). This step is omitted and will depend on your use case.
         */

        /*
         * Step 3: Decrypt the encrypted data key.
         */
        SdkBytes encryptedDataKey = generateDataKeyResponse.ciphertextBlob();
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .ciphertextBlob(encryptedDataKey)
                .build();
        LOG.info(() -> "Decrypting a KMS ciphertext using PQ TLS to protect the plaintext data in transit from KMS");
        DecryptResponse decryptResponse = asyncKMSClient.decrypt(decryptRequest).get();

        /*
         * Step 4: Use the plaintext data key to decrypt your client side data. You can get the plaintext data key by
         * calling decryptResponse.plaintext(). This step is omitted and will depend on your use case.
         */

        /*
         * Cleanup resources from this demo.
         *
         * Schedule deletion of the CMK with imported key material. Because this CMK was created only for this
         * test, we will delete it as part of cleanup. After the CMK is deleted, any ciphertexts encrypted under
         * this CMK are permanently unrecoverable.
         */
        ScheduleKeyDeletionRequest deletionRequest = ScheduleKeyDeletionRequest.builder()
                .keyId(keyId)
                .pendingWindowInDays(7)
                .build();
        ScheduleKeyDeletionResponse deletionResult = asyncKMSClient.scheduleKeyDeletion(deletionRequest).get();
        LOG.info(() -> String.format("CMK %s is schedule to be deleted at %s", keyId, deletionResult.deletionDate()));

        /*
         * Shutdown the SDK and HTTP client. This will free any Java and native resources created for the demo.
         */
        asyncKMSClient.close();
        awsCrtHttpClient.close();
    }
}