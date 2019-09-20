## AWS KMS Post-quantum TLS Example

This repository contains code samples that show how to configure the SDK 2.0 to use the AWS Common Runtime HTTP Client
with hybrid post-quantum TLS with KMS. For more information, see
[Using Post-Quantum TLS with KMS](https://aws.amazon.com/blogs/security/using-post-quantum-tls-with-kms/) (blog) and
[Using Hybrid Post-Quantum TLS with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html)
(documentation).

These samples demonstrate how to use hybrid post-quantum TLS to perform sensitive KMS operations. We consider sensitive
operations to be ones where confidential data is sent over the network that is not protected from quantum advisories.
This includes:
* ImportKey
* GenerateDataKey
* Encrypt
* Decrypt

A large scale quantum computer could be used to recover the TLS session key from classic TLS  key exchanges (RSA, ECDHE,
and FFDHE). The TLS session key is used to encrypt the plaintext data as it is sent over the network. This would reveal
the plaintext in the Encrypt request or the plaintext in the decrypt response. ImportKey's use of the wrapping RSA key
does not protect against a quantum advisory. 

### Prequesites
* Software:
    * Ubuntu 18.04 or Amazon Linux 2 or newer
    * Java Development Kit 8 or newer
    * Maven 3.1.1 or newer
    * Git 2.0 or newer
* AWS credentials set up for your platform, see [Set Up AWS Credentials for Development](https://docs.aws.amazon.com/sdk-for-java/v2/developer-guide/setup-credentials.html)
    * The caller needs the following permissions on the KMS customer master key:
        * kms:CreateKey
        * kms:Decrypt
        * kms:GenerateDataKey
        * kms:GetParametersForImport
        * kms:ImportKeyMaterial
        * kms:ScheduleKeyDeletion
    * To allow CreateKey, use an IAM policy. To allow the other permissions, use a key policy, IAM policy, or a grant.
        * See [Authentication and Access Control for AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html)

### Running the example
```$bash
$ git clone https://github.com/aws-samples/aws-kms-pq-tls-example.git
$ git clone https://github.com/aws/aws-sdk-java-v2.git --branch aws-crt-dev-preview
$ cd aws-sdk-java-v2

# This builds and installs a snapshot (2.7.23-SNAPSHOT) of the SDK (which includes the aws-crt-http-client) into your
# local Maven repository. This demo uses the published Maven artifact (2.7.36) for the rest of the SDK.
$ mvn install -Pquick

$ cd ../aws-kms-pq-tls-example
$ mvn package
$ java -jar target/aws-kms-pq-tls-example-1.0-jar-with-dependencies.jar
```
## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
