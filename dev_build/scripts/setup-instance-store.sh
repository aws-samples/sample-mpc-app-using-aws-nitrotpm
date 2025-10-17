#!/bin/bash

# Wait for udev to settle
udevadm settle

# Find instance store device
INSTANCE_STORE=""
for dev in /dev/nvme*n1; do
  if [ -b "$dev" ] && lsblk -nd -o MODEL "$dev" | grep -q "Amazon EC2 NVMe Instance Storage"; then
    INSTANCE_STORE="$dev"
    break
  fi
done

if [ -z "$INSTANCE_STORE" ]; then
  echo "No instance store device found"
  exit 1
fi

echo "Found instance store at $INSTANCE_STORE"

# Create mount point
mkdir -p /mnt/instance-store

# Unmount if mounted
umount "$INSTANCE_STORE" || true

# Wipe and format
wipefs -a "$INSTANCE_STORE"
mkfs.ext4 -F "$INSTANCE_STORE"

# Mount
mount "$INSTANCE_STORE" /mnt/instance-store

# Create models directory (ownership will be set by ollama-permissions.service)
mkdir -p /mnt/instance-store/models