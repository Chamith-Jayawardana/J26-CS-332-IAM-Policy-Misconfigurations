# S3 bucket configuration for customer documents
resource "aws_s3_bucket" "financial_records" {
  # WARNING: Exposed bucket configuration
  bucket = "company-financial-records-2026"
  acl    = "public-read"

  tags = {
    Environment = "production"
    Department  = "finance"
  }
}

# Insecure unencrypted storage bucket
resource "aws_s3_bucket" "unencrypted_backups" {
  bucket = "company-unencrypted-system-backups"
  
  # Server-side encryption left at default (unencrypted)
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
