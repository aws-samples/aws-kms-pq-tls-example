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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
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
    private static final int AES_TAG_SIZE_BITS = 128;
    private static final int AES_GCM_IV_BYTES = 12;
    private static final byte[] privateData = "MySecretData".getBytes();

    public static byte[] generateSecureRandomBytes(int size) {
        byte[] secureKey = new byte[size];
        SECURE_RANDOM.nextBytes(secureKey);
        return secureKey;
    }

    public static void main(String[] args) throws Exception {
        // Check if the current platform supports Hybrid Post-Quantum TLS (Eg. X25519MLKEM768).
        if(!TlsCipherPreference.TLS_CIPHER_PQ_DEFAULT.isSupported()){
            throw new RuntimeException("PQ TLS is not Supported on the current platform.");
        }

        // Set up a PQ TLS HTTP client that will be used when connecting to AWS
        SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                .postQuantumTlsEnabled(true)
                .build();

        // Set up a KMS Client which will offer hybrid post-quantum TLS with KMS.
        KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                .httpClient(awsCrtHttpClient)
                .build();

        // The KeyId that we are creating and using throughout this demo.
        final String keyId;

        // Example #1: Import a locally generated AES key into KMS over a hybrid post-quantum TLS connection.
        {
            LOG.info(() -> "\nBeginning Example 1...");

            // Step 1: Create an empty CustomerMangedKey (with no key material).
            CreateKeyRequest createRequest = CreateKeyRequest.builder()
                    .origin(OriginType.EXTERNAL)
                    .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                    .build();
            keyId = asyncKMSClient.createKey(createRequest).get().keyMetadata().keyId();
            LOG.info(() -> "1. KMS created empty CustomerManagedKey: " + keyId);

            // Step 2: Get the wrapping key and token required to import the local key material.
            GetParametersForImportRequest getParametersRequest = GetParametersForImportRequest.builder()
                    .keyId(keyId)
                    .wrappingAlgorithm(AlgorithmSpec.RSAES_OAEP_SHA_1)
                    .wrappingKeySpec(WrappingKeySpec.RSA_2048)
                    .build();

            GetParametersForImportResponse getParametersResponse =
                    asyncKMSClient.getParametersForImport(getParametersRequest).get();

            SdkBytes importToken = getParametersResponse.importToken();
            byte[] publicWrappingKey = getParametersResponse.publicKey().asByteArray();
            LOG.info(() -> "2. KMS sent a fresh RSA public wrapping key to client. (Using PQ TLS to protect the RSA key in transit to client.)");

            /*
             * Step 3: Create an ephemeral AES key, and encrypt it with the public RSA wrapping key received from KMS.
             *
             * With KMS ImportKeyMaterial, you are responsible for keeping a durable copy of the key, so we recommend
             * not doing this in production. https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
             */
            byte[] plaintextAesKey = generateSecureRandomBytes(AES_KEY_SIZE_BYTES);
            RSAPublicKey rsaPublicKey = RSAUtils.decodeX509PublicKey(publicWrappingKey);
            byte[] encryptedAesKey = RSAUtils.encryptRSA(rsaPublicKey, plaintextAesKey);
            LOG.info(() -> "3. Client generated a fresh AES key, and encrypted AES key with KMS's public RSA wrapping key.");

            /*
             * Step 4: Import the AES key material into KMS.
             *
             * This is the important call to protect. Your AES key is leaving your client, traveling over the network,
             * first wrapped by an RSA public key, and then also secured by a PQ TLS connection.
             *
             * If you used classical TLS, a large-scale quantum computer would be able to decrypt the TLS session data,
             * recover the RSA-wrapped key material, decrypt the RSA-wrapped key, and recover your plaintext AES key.
             *
             * If this key is compromised, all ciphertexts that use this CMK are also compromised.
             */
            ImportKeyMaterialRequest importRequest = ImportKeyMaterialRequest.builder()
                    .keyId(keyId)
                    .encryptedKeyMaterial(SdkBytes.fromByteArray(encryptedAesKey))
                    .importToken(importToken)
                    .expirationModel(ExpirationModelType.KEY_MATERIAL_EXPIRES)
                    .validTo(Instant.now().plusSeconds(600))
                    .build();
            LOG.info(() -> String.format("4. KMS imported AES key into CustomerMangedKey. (Using PQ TLS to protect RSA-wrapped AES key " +
                    "in transit to KMS.)"));
            asyncKMSClient.importKeyMaterial(importRequest).get();
        }

        // Example #2: Generate an encrypted DataKey, decrypt the DataKey using KMS, and use the DataKey to encrypt data locally.
        {
            LOG.info(() -> "\nBeginning Example 2...");
            /*
             * Step 1: Generate a fresh data encryption key.
             *
             * KMS GenerateDataKey returns both the plaintext key, and a copy of that data key encrypted under the CMK.
             * It is your responsibility to keep the ciphertext so it can be decrypted in the future.
             */
            GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder()
                    .keyId(keyId)
                    .keySpec(DataKeySpec.AES_256)
                    .build();
            LOG.info(() -> String.format("1. KMS sent fresh DataEncryptionKey (wrapped by CMK) to client. (Using PQ TLS to protect DataEncryptionKey in transit to client.)"));
            GenerateDataKeyResponse generateDataKeyResponse = asyncKMSClient.generateDataKey(generateDataKeyRequest).get();

            /*
             * Step 2: Decrypt the encrypted data key.
             *
             * We have access to the plaintext data key within the lifetime of this function, but users are
             * recommended to only store the ciphertext blob. Call KMS to decrypt the ciphertext as if we had stored
             * only the ciphertext, and were calling to decrypt it at a later time.
             */
            SdkBytes encryptedDataKey = generateDataKeyResponse.ciphertextBlob();
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(encryptedDataKey)
                    .build();
            LOG.info(() -> "2. Client issued request to KMS to decrypt DataEncryptionKey. (Using PQ TLS to protect DataEncryptionKey in transit to client.)");
            byte[] plaintextDataKey = asyncKMSClient.decrypt(decryptRequest).get().plaintext().asByteArray();

            // Step 3: Use the plaintext data key to encrypt some client-side data.
            byte[] iv = generateSecureRandomBytes(AES_GCM_IV_BYTES);
            Cipher aesEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
            aesEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(plaintextDataKey, "AES"), new GCMParameterSpec(AES_TAG_SIZE_BITS, iv));
            byte[] encryptedData = aesEncrypt.doFinal(privateData);
            LOG.info(() -> "3. Client encrypted local data with DataEncryptionKey.");

            // Step 4: Use the plaintext data key to decrypt client-side data.
            Cipher aesDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
            aesDecrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(plaintextDataKey, "AES"), new GCMParameterSpec(AES_TAG_SIZE_BITS, iv));
            byte[] decryptedData = aesDecrypt.doFinal(encryptedData);
            boolean decryptedSuccessfully = Arrays.equals(privateData, decryptedData);

            if (!decryptedSuccessfully) {
                throw new RuntimeException("Decrypted data does not match encrypted data");
            }

            LOG.info(() -> String.format("4. Client decrypted local data with DataEncryptionKey."));
        }

        /*
         * Clean up resources from this demo.
         *
         * Schedule deletion of the CMK that contains imported key material. Because this CMK was created only for this
         * test, we will delete it as part of cleanup. After the CMK is deleted, any ciphertexts encrypted under
         * this CMK are permanently unrecoverable.
         */
        LOG.info(() -> "\nEnd of Demo. Cleaning up KMS resources...");
        ScheduleKeyDeletionRequest deletionRequest = ScheduleKeyDeletionRequest.builder()
                .keyId(keyId)
                .pendingWindowInDays(7)
                .build();
        ScheduleKeyDeletionResponse deletionResult = asyncKMSClient.scheduleKeyDeletion(deletionRequest).get();
        LOG.info(() -> String.format("1. KMS has scheduled CustomerManagedKey %s to be deleted at %s", keyId, deletionResult.deletionDate()));

        /*
         * Shut down the SDK and HTTP client. This will free any Java and native resources created for the demo.
         */
        asyncKMSClient.close();
        awsCrtHttpClient.close();
    }
}