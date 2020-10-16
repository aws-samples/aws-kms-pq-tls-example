## AWS KMS Hybrid Post-Quantum TLS Example

This repository contains code samples that show how to configure the AWS SDK 2.0 to use the AWS Common Runtime HTTP 
Client with hybrid post-quantum (PQ) TLS with AWS Key Management Service (KMS). For more information, see
[Using Post-Quantum TLS with KMS](https://aws.amazon.com/blogs/security/post-quantum-tls-now-supported-in-aws-kms/) (blog) and
[Using Hybrid Post-Quantum TLS with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html)
(documentation).

If a large-scale quantum computer is ever built, it could recover the TLS session key from classic TLS key exchanges
(RSA, ECDHE and FFDHE). The TLS session key is used to encrypt data as it is sent over the network. As of 2019, the
largest quantum computer contains fewer than 100 qubits and lacks error correction capability. It is believed you would
need millions of noisy qubits to successfully run Shor's algorithm on keys the size that are used today. See
[How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits](https://arxiv.org/pdf/1905.09749.pdf) for
more information on the analysis of quantum computing hardware requirements.

These samples demonstrate how to use hybrid post-quantum TLS to perform sensitive KMS operations. We consider sensitive
operations to be ones where confidential data is sent over the network that is not protected from a quantum adversary.
These include, but may not be limited to:
* `ImportKeyMaterial`
* `GenerateDataKey`
* `Encrypt`
* `Decrypt`
* `CreateCustomKeyStore`
* `UpdateCustomKeyStore`

For example, in an `Encrypt` call, the client sends a plaintext message to be encrypted with a KMS CMK. The message is
always protected in transit by TLS, but without PQ TLS, a quantum adversary could recover the plaintext message by using
the following procedure:
1. Record the TLS key exchange and session data
2. Research, develop, and build a large-scale quantum computer
2. Use a large-scale quantum computer to recover the TLS session key
1. Use the TLS session key to decrypt the session data
1. Inspect the session data and recover the plaintext message from the request

`Decrypt`, `GenerateDataKey`, `CreateCustomKeyStore`, and `UpdateCustomKeyStore` are vulnerable to the same type of 
attack, when sensitive plaintext is either transmitted by the client or returned by KMS over TLS. In an
`ImportKeyMaterial` request, the client sends an AES key wrapped with RSA to KMS. Without PQ TLS, an attacker could
recover the wrapped key using the steps above, and use another quantum algorithm to break RSA and recover the plaintext
AES key. After they have the plaintext key they can decrypt any ciphertext from KMS that uses the key.

### Prerequisites for the Java example
* Software:
  *   Ubuntu 18.04 or Amazon Linux 2 or later
  *   x86 based processor
  *   Java Development Kit 8 or later
  *   Maven 3.1.1 or later
  *   Git 2.0 or later
* AWS credentials set up for your platform, see [Set Up AWS Credentials for Development](https://docs.aws.amazon.com/sdk-for-java/v2/developer-guide/setup-credentials.html)
    * The caller needs the following KMS permissions in an IAM policy:
        * kms:CreateKey
        * kms:Decrypt
        * kms:GenerateDataKey
        * kms:GetParametersForImport
        * kms:ImportKeyMaterial
        * kms:ScheduleKeyDeletion
  *   See [Using IAM Policies with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html)
  *   An easy way to get credentials on a test EC2 host is by attaching a IAM role during setup or attaching one to a
      running host, See
      [IAM Roles for Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)

### Running the example
```$bash
$ git clone https://github.com/aws-samples/aws-kms-pq-tls-example.git
$ cd aws-kms-pq-tls-example
$ mvn package
$ java -jar target/aws-kms-pq-tls-example-1.0-jar-with-dependencies.jar
```
## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
