#!/bin/bash

usage() {
  echo "Usage: $0 -r INSTANCE_ROLE --region REGION | --instance-role INSTANCE_ROLE --region REGION"
  echo "  -r, --instance-role        Specify the ARN of the instance role"
  echo "  --region                   Specify the AWS region"
  exit 1
}

# Get AWS account ID for root ARN
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if [ -z "$ACCOUNT_ID" ]; then
  echo "Error: Failed to get AWS account ID"
  exit 1
fi
ADMIN_ROLE="arn:aws:iam::${ACCOUNT_ID}:root"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--instance-role) INSTANCE_ROLE="$2"; shift ;;
    --region) AWS_REGION="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "$INSTANCE_ROLE" ] || [ -z "$AWS_REGION" ]; then
  echo "Error: Instance role ARN and AWS region are required."
  usage
fi



# Retry logic for KMS key creation to handle IAM role propagation delays
create_kms_key_with_retry() {
  local policy_file=$1
  local max_attempts=3
  local attempt=1
  local sleep_interval=2

  while [ $attempt -le $max_attempts ]; do
    local key_output=$(aws kms create-key \
      --region "$AWS_REGION" \
      --description "NitroTPM attestation example key" \
      --policy file://"$policy_file" 2>&1)
    local exit_code=$?

    # Check if output contains error information (AWS CLI can return 0 even with errors)
    if echo "$key_output" | grep -q "An error occurred"; then
      # Check if the error is due to invalid principals (IAM propagation issue)
      if echo "$key_output" | grep -q "invalid principals"; then
        sleep $sleep_interval
        attempt=$((attempt + 1))
        continue
      fi

      # For any other error, fail immediately
      echo "Error: AWS command failed with non-retryable error: $key_output"
      return 1
    fi

    # If exit code is non-zero and no clear error pattern, treat as error
    if [ $exit_code -ne 0 ]; then
      echo "Error: AWS command failed: $key_output"
      return 1
    fi

    echo "$key_output"
    return 0
  done

  echo "Error: Failed to create KMS key after $max_attempts attempts"
  echo "Last output: $key_output"
  return 1
}

KEY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow access for Key Administrators",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${ADMIN_ROLE}"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
)

KEY_POLICY_FILE=$(mktemp -t kms_policy.XXXXXX.json)
echo "$KEY_POLICY" > "$KEY_POLICY_FILE"
echo "KMS policy written to $KEY_POLICY_FILE"

echo "Creating KMS key..."
KEY_OUTPUT=$(create_kms_key_with_retry "$KEY_POLICY_FILE")
if [ $? -ne 0 ]; then
  echo "Error: Failed to create KMS key: $KEY_OUTPUT"
  exit 1
fi

echo "AWS KMS command completed. Processing output..."
KEY_ID=$(echo "$KEY_OUTPUT" | jq -r '.KeyMetadata.KeyId')
echo "KMS key created with ID: $KEY_ID"

# Clean up temporary policy file
rm -f "$KEY_POLICY_FILE"