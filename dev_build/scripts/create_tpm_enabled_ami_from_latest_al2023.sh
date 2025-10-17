#!/bin/bash

# Usage: ./create_ami_from_snapshot_with_tpm.sh --arch x86_64 --source-region us-east-1 --dest-region us-east-2
# Example: ./create_ami_from_snapshot_with_tpm.sh --arch arm64 --source-region us-west-2 --dest-region us-east-1

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --source-region)
            SOURCE_REGION="$2"
            shift 2
            ;;
        --dest-region)
            DEST_REGION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

if [ -z "$ARCH" ] || [ -z "$SOURCE_REGION" ] || [ -z "$DEST_REGION" ]; then
    echo "Usage: $0 --arch <x86_64|arm64> --source-region <region> --dest-region <region>"
    exit 1
fi

# Find latest Amazon Linux 2023 AMI with UEFI support
AMI_ID=$(aws ec2 describe-images \
    --region $SOURCE_REGION \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023.*-kernel-6.1-$ARCH" \
              "Name=architecture,Values=$ARCH" \
              "Name=state,Values=available" \
              "Name=boot-mode,Values=uefi,uefi-preferred" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)

echo "Found latest AL2023 AMI: $AMI_ID"

# Get snapshot ID from the AMI
SNAPSHOT_ID=$(aws ec2 describe-images \
    --region $SOURCE_REGION \
    --image-ids $AMI_ID \
    --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' \
    --output text)

echo "Source snapshot: $SNAPSHOT_ID"

# Copy snapshot to destination region
NEW_SNAPSHOT_ID=$(aws ec2 copy-snapshot \
    --region $DEST_REGION \
    --source-snapshot-id $SNAPSHOT_ID \
    --source-region $SOURCE_REGION \
    --description "TPM-enabled AL2023 snapshot" \
    --query 'SnapshotId' \
    --output text)

echo "Copied snapshot: $NEW_SNAPSHOT_ID"

# Wait for snapshot to complete
echo "Waiting for snapshot to complete..."
aws ec2 wait snapshot-completed --region $DEST_REGION --snapshot-ids $NEW_SNAPSHOT_ID

# Create TPM-enabled AMI
TPM_AMI_ID=$(aws ec2 register-image \
    --region $DEST_REGION \
    --name "AL2023-TPM-$ARCH-$(date +%Y%m%d-%H%M%S)" \
    --description "TPM-enabled Amazon Linux 2023 $ARCH" \
    --architecture $ARCH \
    --root-device-name "/dev/xvda" \
    --block-device-mappings "[{\"DeviceName\": \"/dev/xvda\",\"Ebs\":{\"SnapshotId\":\"$NEW_SNAPSHOT_ID\"}}]" \
    --boot-mode uefi \
    --tpm-support v2.0 \
    --query 'ImageId' \
    --output text)

echo "Created TPM-enabled AMI: $TPM_AMI_ID"