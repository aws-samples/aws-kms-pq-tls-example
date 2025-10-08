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
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.utils.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static software.amazon.awssdk.services.kms.model.KeySpec.*;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ML_DSA_SHAKE_256;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

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
    private static final byte[] msgToSign = "Hello World!".getBytes();
    private static final ArrayList<String> keysToCleanup = new ArrayList<>();

    public static byte[] generateSecureRandomBytes(int size) {
        byte[] secureKey = new byte[size];
        SECURE_RANDOM.nextBytes(secureKey);
        return secureKey;
    }

    private static void deleteKeys(KmsAsyncClient asyncKMSClient, List<String> keyIds) throws Exception {
        LOG.info(() -> "\nEnd of Demo. Cleaning up KMS resources...");
        for (String keyId : keyIds) {
            ScheduleKeyDeletionRequest deletionRequest = ScheduleKeyDeletionRequest.builder()
                    .keyId(keyId)
                    .pendingWindowInDays(7)
                    .build();
            ScheduleKeyDeletionResponse deletionResult = asyncKMSClient.scheduleKeyDeletion(deletionRequest).get();
            LOG.info(() -> String.format("   KMS has scheduled Key %s to be deleted at %s", keyId, deletionResult.deletionDate()));
        }
        LOG.info(() -> "\n");
    }

    /**
     * Imports an AES key into KMS.
     *
     * @param asyncKMSClient The KMS Client to use when connecting to KMS
     * @param plaintextAesKey The AES key to import into KMS
     * @return The KMS KeyId of the imported key.
     */
    private static String kmsImportAesKeyExample(KmsAsyncClient asyncKMSClient, byte[] plaintextAesKey) throws Exception {
        LOG.info(() -> "\nExample 1: Beginning importAesKeyExample()...");

        // Step 1: Create an empty external CustomerMangedKey (with no key material).
        CreateKeyRequest createRequest = CreateKeyRequest.builder()
                .origin(OriginType.EXTERNAL)
                .description("Test key for aws-kms-pq-tls-example. Feel free to delete this.")
                .build();
        final String keyId = asyncKMSClient.createKey(createRequest).get().keyMetadata().keyId();
        LOG.info(() -> "1. KMS created empty CustomerManagedKey: " + keyId);
        keysToCleanup.add(keyId);

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
        LOG.info(() -> "2. KMS sent a fresh RSA public wrapping key to client. (Using PQ TLS to protect the RSA key sent to client.)");

        /*
         * Step 3: Encrypt plaintext key with the public RSA wrapping key received from KMS.
         *
         * With KMS ImportKeyMaterial, you are responsible for keeping a durable copy of the key, so we recommend
         * not doing this in production. https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
         */
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


        return keyId;
    }

    /**
     * Exports an AES key out of KMS encrypted with the specified keyId.
     * @param asyncKMSClient The KMS client to use when connecting to KMS
     * @param keyId The pre-existing KMS KeyId to use to encrypt the exported AES key
     * @return The encrypted AES key generated by KMS
     * @throws Exception
     */
    private static byte[] kmsExportAesKeyExample(KmsAsyncClient asyncKMSClient, String keyId) throws Exception {
        LOG.info(() -> "\nExample 2: Beginning exportAesKeyExample()...");
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

        byte[] kmsGeneratedEncryptedAesKey = generateDataKeyResponse.ciphertextBlob().asByteArray();
        byte[] kmsGeneratedPlaintextAesKey = generateDataKeyResponse.plaintext().asByteArray();

        if (kmsGeneratedPlaintextAesKey.length != AES_KEY_SIZE_BYTES) {
            throw new RuntimeException("KMS returned AES key of invalid key length: " + kmsGeneratedPlaintextAesKey.length);
        }

        // Step 3: Use the plaintext data key to encrypt some client-side data.
        byte[] iv = generateSecureRandomBytes(AES_GCM_IV_BYTES);
        Cipher aesEncrypt = Cipher.getInstance("AES/GCM/NoPadding");
        aesEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kmsGeneratedPlaintextAesKey, "AES"), new GCMParameterSpec(AES_TAG_SIZE_BITS, iv));
        byte[] encryptedData = aesEncrypt.doFinal(privateData);
        LOG.info(() -> "2. Client encrypted local data with DataEncryptionKey.");

        // Step 4: Use the plaintext data key to decrypt client-side data.
        Cipher aesDecrypt = Cipher.getInstance("AES/GCM/NoPadding");
        aesDecrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kmsGeneratedPlaintextAesKey, "AES"), new GCMParameterSpec(AES_TAG_SIZE_BITS, iv));
        byte[] decryptedData = aesDecrypt.doFinal(encryptedData);
        boolean decryptedSuccessfully = Arrays.equals(privateData, decryptedData);

        if (!decryptedSuccessfully) {
            throw new RuntimeException("Decrypted data does not match encrypted data");
        }

        LOG.info(() -> String.format("3. Client decrypted local data with DataEncryptionKey."));

        // NOTE: Client is now responsible for durable storing the ciphertext blob alongside any data that they encrypt
        // with the plaintext AES key. This is skipped for the purposes of this demonstration code.
        return kmsGeneratedEncryptedAesKey;
    }

    private static void kmsSignVerifyExample(KmsAsyncClient asyncKMSClient, KeySpec keySpec, SigningAlgorithmSpec signingSpec) throws Exception {
        LOG.info(() -> "\nExample 3: Beginning signVerifyExample()...");
        final String signingKey;

        // Step 1: Create an empty CustomerMangedKey (with no key material).
        CreateKeyRequest createRequest = CreateKeyRequest.builder()
                .origin(OriginType.AWS_KMS)
                .description("Test " + keySpec.toString() + " key for aws-kms-pq-tls-example. Feel free to delete this.")
                .keyUsage(KeyUsageType.SIGN_VERIFY)
                .keySpec(keySpec)
                .build();
        signingKey = asyncKMSClient.createKey(createRequest).get().keyMetadata().keyId();
        LOG.info(() -> "1. KMS created " + keySpec.name() + " Signing Key with KeyId: " + signingKey);
        keysToCleanup.add(signingKey);

        SignRequest signRequest = SignRequest.builder()
                .keyId(signingKey)
                .message(SdkBytes.fromByteArray(msgToSign))
                .messageType(MessageType.RAW)
                .signingAlgorithm(signingSpec)
                .build();

        SignResponse signResponse = asyncKMSClient.sign(signRequest).get();
        byte[] signatureBytes = signResponse.signature().asByteArray();
        LOG.info(() -> "2. KMS signed message using SigningSpec " + signingSpec.name() + " and generated a signature with a length of " + signatureBytes.length + " bytes");

        VerifyRequest verifyRequest = VerifyRequest.builder()
                .keyId(signingKey)
                .message(SdkBytes.fromByteArray(msgToSign))
                .messageType(MessageType.RAW)
                .signature(SdkBytes.fromByteArray(signatureBytes))
                .signingAlgorithm(signingSpec)
                .build();

        VerifyResponse verifyResponse = asyncKMSClient.verify(verifyRequest).get();
        LOG.info(() -> "3. KMS verified signature. SignatureValid=" + verifyResponse.signatureValid());
    }

    public static void main(String[] args) throws Exception {
        LOG.info(() -> "\n------------------------------------------------------------------------");
        LOG.info(() -> "Starting AwsKmsPqTlsExample");
        LOG.info(() -> "------------------------------------------------------------------------");

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

        try {
            // Example #1: Import a locally generated AES key into KMS over a hybrid post-quantum TLS connection.
            byte[] locallyGeneratedAesKey = generateSecureRandomBytes(AES_KEY_SIZE_BYTES);
            String keyId = kmsImportAesKeyExample(asyncKMSClient, locallyGeneratedAesKey);

            // Example #2: Generate an AES key from KMS to allow encrypting/decrypting data locally.
            byte[] kmsGeneratedEncryptedAesKey = kmsExportAesKeyExample(asyncKMSClient, keyId);
            // NOTE: kmsGeneratedEncryptedAesKey should normally be durably stored alongside any data that is encrypted
            // For this demonstration, we skip durably storing it, as the key will be immediately deleted at the end
            // of this demo.

            // Example #3: Sign and Verify a message using KMS
            kmsSignVerifyExample(asyncKMSClient, RSA_2048, RSASSA_PKCS1_V1_5_SHA_256);
            kmsSignVerifyExample(asyncKMSClient, ML_DSA_65, ML_DSA_SHAKE_256);

        } finally{
            deleteKeys(asyncKMSClient, keysToCleanup);
            asyncKMSClient.close();
            awsCrtHttpClient.close();
        }
    }
}