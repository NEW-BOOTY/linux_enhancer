/*
 * Terraform Outputs
 *
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */

output "backup_bucket" {
  value = aws_s3_bucket.backups.id
}

output "kms_key" {
  value = aws_kms_key.backup_key.arn
}

output "iam_role" {
  value = aws_iam_role.backup_role.name
}
