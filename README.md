## AWS KMS Post-quantum TLS Example

Demo code to setup the Java SDK 2.0 to use Post-quantum TLS with KMS. See [this blog post](https://aws.amazon.com/blogs/security/using-post-quantum-tls-with-kms/) for more info.

This code shows how to depend on the new SDK and HTTP client, how to configure it, and then uses it for an import key test.

### Prequesites
1. Java Development Kit 8 or later, Maven 3.1.1 or later, and Git 2.0 or later
1. AWS credentials setup for your platform, see [Set Up AWS Credentials for Development](https://docs.aws.amazon.com/sdk-for-java/v2/developer-guide/setup-credentials.html).
    1. The credentials will need KMS CreateKey, GetParametersForImport, ImportKey, Encrypt, Decrypt, and ScheduleKeyDeletion permissions.
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
