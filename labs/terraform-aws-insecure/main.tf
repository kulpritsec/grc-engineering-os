terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "mock_access_key"
  secret_key = "mock_secret_key"

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_vpc" "lab" {
  cidr_block = "10.20.0.0/16"

  tags = {
    Name = "grcos-insecure-lab"
  }
}

# Deliberately insecure: SSH exposed to the entire internet.
resource "aws_security_group" "admin_open" {
  name        = "grcos-admin-open"
  description = "Intentionally insecure GRC OS lab"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "Unrestricted SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Deliberately missing an encryption configuration.
resource "aws_s3_bucket" "evidence" {
  bucket        = "grcos-insecure-evidence-example"
  force_destroy = true
}

# Deliberately disables all S3 public-access protections.
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Deliberately grants anonymous object-read access.
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
      }
    ]
  })
}
