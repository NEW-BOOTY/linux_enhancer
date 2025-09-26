const cdk = require('aws-cdk-lib');
const s3 = require('aws-cdk-lib/aws-s3');
const kms = require('aws-cdk-lib/aws-kms');
const iam = require('aws-cdk-lib/aws-iam');

class S3Stack extends cdk.Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const key = new kms.Key(this, 'BackupKey', { enableKeyRotation: true });

    const bucket = new s3.Bucket(this, 'Backups', {
      bucketName: props.backupBucketName,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
      versioned: true,
    });

    const role = new iam.Role(this, 'BackupRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
    });

    new cdk.CfnOutput(this, 'BucketName', { value: bucket.bucketName });
    new cdk.CfnOutput(this, 'KmsKey', { value: key.keyArn });
    new cdk.CfnOutput(this, 'IamRole', { value: role.roleName });
  }
}

module.exports = { S3Stack };
