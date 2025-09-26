provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "backups" {
  bucket = var.backup_bucket_name
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.backup_key.arn
      }
    }
  }
}

resource "aws_kms_key" "backup_key" {
  description             = "Backup KMS Key"
  deletion_window_in_days = 10
}

resource "aws_iam_role" "backup_role" {
  name               = "backup_role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
