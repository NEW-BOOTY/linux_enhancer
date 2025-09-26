/*
 * Terraform Variables
 *
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */

variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "backup_bucket_name" {
  description = "Name of backup bucket"
  default     = "linux-enhancer-backups"
}
