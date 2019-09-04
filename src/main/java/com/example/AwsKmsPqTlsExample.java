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

import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.SocketOptions;
import software.amazon.awssdk.crt.io.TlsCipherPreference;
import software.amazon.awssdk.crt.io.TlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.KeyListEntry;
import software.amazon.awssdk.services.kms.model.ListKeysResponse;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.utils.Logger;

public class AwsKmsPqTlsExample {
    private static final Logger log = Logger.loggerFor(AwsKmsPqTlsExample.class);

    public static void main(String[] args) throws Exception {

        TlsCipherPreference cipherPreferences = null;
        if (TlsContextOptions.isCipherPreferenceSupported(TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06)) {
            log.info(() -> "Post-quantum ciphers are supported and will be used!");
            cipherPreferences = TlsCipherPreference.TLS_CIPHER_KMS_PQ_TLSv1_0_2019_06;
        } else {
            log.warn(() -> "Post-quantum ciphers are not supported, falling back to classic cipher suites.");
            cipherPreferences = TlsCipherPreference.TLS_CIPHER_SYSTEM_DEFAULT;
        }
        try (ClientBootstrap bootstrap = new ClientBootstrap(1)) {
            try (SocketOptions socketOptions = new SocketOptions()) {
                try (TlsContextOptions contextOptions = new TlsContextOptions().withCipherPreference(cipherPreferences)) {
                    try (TlsContext tlsContext = new TlsContext(contextOptions)) {
                        try (SdkAsyncHttpClient awsCrtHttpClient = AwsCrtAsyncHttpClient.builder()
                                .bootstrap(bootstrap)
                                .socketOptions(socketOptions)
                                .tlsContext(tlsContext)
                                .build()) {
                            try (KmsAsyncClient asyncKMSClient = KmsAsyncClient.builder()
                                    .httpClient(awsCrtHttpClient)
                                    .build()) {

                                final ListKeysResponse response = asyncKMSClient.listKeys().get();
                                log.info(() -> String.format("Found %d keys and %s have more pages.",
                                        response.keys().size(), response.truncated()? "do" : "do not"));
                                
                                for(KeyListEntry key : response.keys()){
                                    log.info(() -> key.keyArn());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
