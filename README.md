## AWS KMS Hybrid Post-Quantum TLS Example

This repository contains code samples that show how to configure the AWS SDK 2.0 to use the AWS Common Runtime HTTP Client
with hybrid post-quantum (PQ) TLS with AWS Key Management Service (KMS). For more information, see
[Using Post-Quantum TLS with KMS](https://aws.amazon.com/blogs/security/using-post-quantum-tls-with-kms/) (blog) and
[Using Hybrid Post-Quantum TLS with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html)
(documentation).

These samples demonstrate how to use hybrid post-quantum TLS to perform sensitive KMS operations. We consider sensitive
operations to be ones where confidential data is sent over the network that is not protected from a quantum adversary.
These include, but may not be limited to:
* `ImportKeyMaterial`
* `GenerateDataKey`
* `Encrypt`
* `Decrypt`
* `CreateCustomKeyStore`
* `UpdateCustomKeyStore`

A large-scale quantum computer could recover the TLS session key from classic TLS key exchanges (ECDHE and FFDHE). The
TLS session key is used to encrypt data as it is sent over the network. We demonstrate how to configure an HTTP client
to use PQ TLS with KMS, which prevents a quantum computer from recovering sensitive data.

For example, in an `Encrypt` call, the client sends a plaintext message to be encrypted with a KMS CMK. The message is
always protected in transit by TLS, but without PQ TLS, a quantum adversary could recover the plaintext message by using
the following procedure:
1. Record the TLS key exchange and session data
1. Use a large-scale quantum computer to recover the TLS session key
1. Use the TLS session key to decrypt the session data
1. Inspect the session data and recover the plaintext message from the request

`Decrypt`, `GenerateDataKey`, `CreateCustomKeyStore`, and `UpdateCustomKeyStore` are vulnerable to the same type of attack,
when sensitive plaintext is either transmitted by the client or returned by KMS over TLS. In an `ImportKeyMaterial` request,
the client sends an AES key wrapped with RSA to KMS. Without PQ TLS, an attacker could recover the wrapped key using the
steps above, and use another quantum algorithm to break RSA and recover the plaintext AES key. After they have the plaintext
key they can decrypt any ciphertext from KMS that uses the key.

### Prerequisites for the Java example
* Software:
    * Ubuntu 18.04 or Amazon Linux 2 or later
    * Java Development Kit 8 or later
    * Maven 3.1.1 or later
    * Git 2.0 or later
* AWS credentials set up for your platform, see [Set Up AWS Credentials for Development](https://docs.aws.amazon.com/sdk-for-java/v2/developer-guide/setup-credentials.html)
    * The caller needs the following KMS permissions in an IAM policy:
        * kms:CreateKey
        * kms:Decrypt
        * kms:GenerateDataKey
        * kms:GetParametersForImport
        * kms:ImportKeyMaterial
        * kms:ScheduleKeyDeletion
    * See [Using IAM Policies with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html)

### Running the example
```$bash
$ git clone https://github.com/aws-samples/aws-kms-pq-tls-example.git
$ git clone https://github.com/aws/aws-sdk-java-v2.git --branch aws-crt-dev-preview
$ cd aws-sdk-java-v2

# This builds and installs a snapshot (2.7.23-SNAPSHOT) of the Java SDK 2.0, which includes the aws-crt-client, into your
# local Maven repository. This example uses the published Maven artifact (2.7.36) for the rest of the SDK.
$ mvn install -Pquick

$ cd ../aws-kms-pq-tls-example
$ mvn package
$ java -jar target/aws-kms-pq-tls-example-1.0-jar-with-dependencies.jar
```
## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
