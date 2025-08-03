# Random suffix per rendere il nome bucket univoco
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Bucket S3 principale
resource "aws_s3_bucket" "musify_bucket" {
  bucket = "musify-platform-bucket-${random_id.bucket_suffix.hex}"
}

# Versioning abilitato
resource "aws_s3_bucket_versioning" "musify_bucket_versioning" {
  bucket = aws_s3_bucket.musify_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CORS base per permettere accesso dal frontend
resource "aws_s3_bucket_cors_configuration" "musify_cors" {
  bucket = aws_s3_bucket.musify_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "HEAD"]
    allowed_origins = ["*"] # In produzione, specifica i tuoi domini esatti
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# Block public access (sicurezza)
resource "aws_s3_bucket_public_access_block" "musify_bucket_pab" {
  bucket = aws_s3_bucket.musify_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Output per vedere il nome del bucket creato
output "bucket_name" {
  description = "Nome del bucket S3 creato"
  value       = aws_s3_bucket.musify_bucket.id
}

output "bucket_arn" {
  description = "ARN del bucket S3"
  value       = aws_s3_bucket.musify_bucket.arn
}

output "bucket_region" {
  description = "Regione del bucket S3"
  value       = aws_s3_bucket.musify_bucket.region
}