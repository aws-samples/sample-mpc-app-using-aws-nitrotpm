#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -b BUCKET_NAME -r REGION | --bucket BUCKET_NAME --region REGION"
  echo "  -b, --bucket    Specify the S3 bucket name"
  echo "  -r, --region    Specify the AWS region (e.g., us-east-1)"
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -b|--bucket) BUCKET_NAME="$2"; shift ;;
    -r|--region) REGION="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "${BUCKET_NAME:-}" ] || [ -z "${REGION:-}" ]; then
  echo "Error: Bucket name and region are required."
  usage
fi

# Validate bucket name
if [[ ! $BUCKET_NAME =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || [[ ${#BUCKET_NAME} -lt 3 ]] || [[ ${#BUCKET_NAME} -gt 63 ]]; then
  echo "Error: Invalid bucket name. Bucket names must:"
  echo "  - Be between 3 and 63 characters long"
  echo "  - Contain only lowercase letters, numbers, dots (.), and hyphens (-)"
  echo "  - Begin and end with a letter or number"
  exit 1
fi

echo "Creating S3 bucket: $BUCKET_NAME in region: $REGION"

# Create the bucket with versioning enabled and server-side encryption
if [[ "$REGION" == "us-east-1" ]]; then
  # Special case for us-east-1 as it doesn't accept LocationConstraint
  aws s3api create-bucket \
    --bucket "$BUCKET_NAME" \
    --region "$REGION"
else
  aws s3api create-bucket \
    --bucket "$BUCKET_NAME" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION"
fi

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled

# Enable server-side encryption
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }
    ]
  }'

# Block public access
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "S3 bucket created with Name: $BUCKET_NAME"
