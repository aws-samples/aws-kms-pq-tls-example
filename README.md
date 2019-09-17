## AWS KMS Post-quantum TLS Example

Demo code to configure the Java SDK 2.0 to use hybrid post-quantum TLS with KMS. For more information, see
[this blog post](https://aws.amazon.com/blogs/security/using-post-quantum-tls-with-kms/).

This code shows how to create a dependency on the new AWS SDK for Java 2.0 and HTTP client and how to configure it to
use hybrid post-quantum cipher suites. Then, it uses the configured KMS client in an import key test.

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
        * kms:Encrypt
        * kms:GetParametersForImport
        * kms:ImportKey
        * kms:ScheduleKeyDeletion
    * To allow CreateKey, use an IAM policy. To allow the other permissions, use a key policy, IAM policy, or a grant.
        * See [Authentication and Access Control for AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html)

### Running the example
```$bash
$ git clone https://github.com/aws-samples/aws-kms-pq-tls-example.git
$ git clone https://github.com/aws/aws-sdk-java-v2.git --branch aws-crt-dev-preview
$ cd aws-sdk-java-v2

# This builds and installs the a snapshot of the SDK (which includes the aws-crt-http-client) into your local Maven
# repository. This demo uses the published Maven artifact for the rest of the SDK.
$ mvn install -Pquick

$ cd ../aws-kms-pq-tls-example
$ mvn package
$ java -jar target/aws-kms-pq-tls-example-1.0-jar-with-dependencies.jar
```
## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.
