# AWS CDK App - GOD-MODE++
# Defines infra for S3 + IAM via Python CDK
#
# Copyright © 2025 Devin B. Royal.
# All Rights Reserved.

from aws_cdk import (
    aws_s3 as s3,
    aws_iam as iam,
    aws_kms as kms,
    core,
)

class EnhancerStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        key = kms.Key(self, "BackupKey",
            enable_key_rotation=True,
            alias="enhancer-backup-key"
        )

        bucket = s3.Bucket(self, "BackupBucket",
            versioned=True,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=key,
            lifecycle_rules=[s3.LifecycleRule(
                expiration=core.Duration.days(90)
            )]
        )

        role = iam.Role(self, "BackupRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )

        bucket.grant_read_write(role)

app = core.App()
EnhancerStack(app, "EnhancerStack")
app.synth()
