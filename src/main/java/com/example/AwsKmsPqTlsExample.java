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

/*
 * This Java code shows how to configure the AWS Java SDK 2.0 with the AWS Common Runtime (CRT) HTTP client and PQ
 * cipher suites. Then, it uses the KMS client to import key material into a customer master key (CMK), generate a data
 * key under that CMK, and decrypt the encrypted data key.
 */
public class AwsKmsPqTlsExample {
    private static final Logger LOG = Logger.loggerFor(AwsKmsPqTlsExample.class);
    private static final Random SECURE_RANDOM = new SecureRandom();
    private static final int AES_KEY_SIZE_BYTES = 256 / 8;

    public static void main(String[] args) throws Exception {
        /*
         * Set up a PQ TLS HTTP client that will be used in the rest of the example. This will optimistically enable
         * hybrid post-quantum TLS if post-quantum algorithms are supported on the current platform, otherwise the
         * default TLS configuration will be used.
         */
        SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .postQuantumTlsEnabled(true)
                .build();
        /*
         * Set up a Java SDK 2.0 KMS Client which will use hybrid post-quantum TLS for all connections to KMS.
         */
        KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                .httpClient(awsCrtHttpClient)
                .build();

        /*
         * Import key material workflow with hybrid post-quantum TLS
         *
         * Step 1: Create an external CMK with no key material
         */
        CreateKeyRequest createRequest = CreateKeyRequest.builder()
                .origin(OriginType.EXTERNAL)
                .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                .build();
        CreateKeyResponse createResponse = asyncKMSClient.createKey(createRequest).get();
        String keyId = createResponse.keyMetadata().keyId();
        LOG.info(() -> "Created CMK " + keyId);

        /*
         * Step 2: Get the wrapping key and token required to import the local key material. The AlgorithmSpec determines
         * how we must wrap the local key material using the public key from KMS.
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
         * Create an ephemeral AES key. You should never do this in production. With KMS ImportKeyMaterial, you are
         * responsible for keeping a durable copy of the key.
         * https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
         *
         * The plaintextAesKey exists only for the lifetime of this function. This example key material will expire from
         * KMS in 10 minutes. This is the 'validTo(Instant.now().plusSeconds(600))' in the ImportKeyMaterial call below.
         */
        byte[] plaintextAesKey = new byte[AES_KEY_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(plaintextAesKey);

        /*
         * Use the wrapping key to encrypt the local key material. Then use the token to import the wrapped key
         * material into KMS.
         *
         * This RSA wrapped key material is protected in transit with PQ TLS. If you use classic TLS, a large-scale
         * quantum computer would be able to decrypt the TLS session data and recover the RSA-wrapped key material. Then
         * it could decrypt the RSA-wrapped key to recover your plaintext AES key.
         */
        RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicKeyBytes);
        byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);

        /*
         * Step 4: Import the key material using the CMK ID, wrapped key material, and import token. This is the
         * important call to protect. Your AES key is leaving your computer and traveling over the network wrapped by an
         * RSA public key and encrypted with PQ TLS.
         *
         * This AES key will be used for all KMS cryptographic operations when you use this CMK. If this key is
         * compromised, all ciphertexts that use this CMK are also compromised.
         */
        ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                .keyId(keyId)
                .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                .importToken(importToken)
                .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                .validTo(Instant.now().plusSeconds(600))
                .build();
        LOG.info(() -> String.format("Importing key material into CMK %s. Using PQ TLS to protect RSA-wrapped AES key " +
                "in transit", keyId));
        asyncKMSClient.importKeyMaterial(importRequest).get();

        /*
         * Sensitive cryptographic operations workflow. Use a KMS CMK to encrypt and decrypt data. The CMK can have any
         * origin (AWS_KMS, EXTERNAL, or AWS_CLOUDHSM). This example reuses the CMK with imported key material that we
         * created in the previous step.
         *
         * Step 1: Generate a data key. KMS GenerateDataKey returns the plaintext data key and a copy of that data key
         * encrypted under the CMK using AES-GCM with 256-bit keys. It is your responsibility to keep the ciphertext so
         * the plaintext data key can be decrypted in the future.
         */
        GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(DataKeySpec.AES_256)
                .build();
        LOG.info(() -> String.format("Generating a data key. Using PQ TLS to protect the plaintext data key in transit. " +
                "The encrypted data key is encrypted under the CMK %s", keyId));
        GenerateDataKeyResponse generateDataKeyResponse = asyncKMSClient.generateDataKey(generateDataKeyRequest).get();

        /*
         * Step 2: Use the plaintext data key for client-side encryption. You can get the plaintext data key by calling
         * generateDataKeyResponse.plaintext(). This step is omitted and will depend on your use case.
         */

        /*
         * Step 3: Decrypt the encrypted data key.
         */
        SdkBytes encryptedDataKey = generateDataKeyResponse.ciphertextBlob();
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .ciphertextBlob(encryptedDataKey)
                .build();
        LOG.info(() -> "Decrypting a KMS ciphertext. Using PQ TLS to protect the plaintext data in transit");
        DecryptResponse decryptResponse = asyncKMSClient.decrypt(decryptRequest).get();

        /*
         * Step 4: Use the plaintext data key to decrypt your client-side data. You can get the plaintext data key by
         * calling decryptResponse.plaintext(). This step is omitted and will depend on your use case.
         */

        /*
         * Clean up resources from this demo.
         *
         * Schedule deletion of the CMK that contains imported key material. Because this CMK was created only for this
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
         * Shut down the SDK and HTTP client. This will free any Java and native resources created for the demo.
         */
        asyncKMSClient.close();
        awsCrtHttpClient.close();
    }
}