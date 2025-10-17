#!/bin/bash

# Install git, python, aws cli, and aws-nitro-tpm-tools
sudo dnf update -y
sudo dnf install -y git python3 python3-pip awscli aws-nitro-tpm-tools tpm2-tools nodejs
sudo dnf clean all
sudo dnf install -y dkms 
sudo systemctl enable --now dkms
if (uname -r | grep -q ^6\\.12\\.); then
  if ( dnf search kernel6.12-headers | grep -q kernel ); then
    sudo dnf install -y kernel6.12-headers-$(uname -r) kernel6.12-devel-$(uname -r) kernel6.12-modules-extra-$(uname -r) kernel6.12-modules-extra-common-$(uname -r) --allowerasing
  else  
    sudo dnf install -y kernel-headers-$(uname -r) kernel-devel-$(uname -r) kernel6.12-modules-extra-$(uname -r) kernel-modules-extra-common-$(uname -r) --allowerasing
  fi
else
  if ( ! cat /etc/dnf/dnf.conf | grep ^exclude | grep -q 6\\.12 ); then
    sudo sed -i '$aexclude=kernel6.12* kernel-headers-6.12* kernel-devel-6.12* kernel-modules-extra-common-6.12* kernel-modules-extra-6.12*' /etc/dnf/dnf.conf
  fi  
  sudo dnf install -y kernel-headers-$(uname -r) kernel-devel-$(uname -r) kernel-modules-extra-$(uname -r) kernel-modules-extra-common-$(uname -r)
fi

if (arch | grep -q x86); then
  ARCH=x86_64
else
  ARCH=sbsa
fi
sudo dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/amzn2023/$ARCH/cuda-amzn2023.repo

sudo dnf module enable -y nvidia-driver:open-dkms
sudo dnf clean expire-cache
sudo dnf install -y nvidia-open 
sudo dnf install -y nvidia-xconfig
sudo dnf install -y cuda-toolkit

# Install CUDA-enabled ollama (Amazon Linux package is CPU-only)
echo "Installing CUDA-enabled ollama"

curl -I https://ollama.com 2>&1 || echo "Network test failed"
echo "Downloading ollama installer for a specific version..."
export OLLAMA_VERSION=0.12.5
if curl -fsSL https://ollama.com/install.sh > /tmp/ollama-install.sh; then
    echo "Download successful, running installer..." 
    if sh /tmp/ollama-install.sh  2>&1; then
        echo "Ollama installation successful"
        which ollama 2>&1 || echo "Ollama not in PATH"
        ls -l /usr/local/bin/ollama  2>&1 || echo "Ollama binaries not found"
    else
        echo "Ollama installation script FAILED"
    fi
else
    echo "Failed to download ollama installer"
fi

echo "Setting up Ollama Chat Interface..."

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    # Download and verify Node.js setup script
    curl -fsSL https://rpm.nodesource.com/setup_18.x -o /tmp/nodejs_setup.sh
    # Review the script before execution (in production, verify checksum)
    sudo bash /tmp/nodejs_setup.sh
    sudo yum install -y nodejs
    rm -f /tmp/nodejs_setup.sh
fi

# Copy setup scripts
echo "Installing setup scripts..."
sudo cp dev_build/scripts/setup-instance-store.sh /usr/local/bin/
sudo cp dev_build/scripts/setup-ollama-permissions.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/setup-instance-store.sh
sudo chmod +x /usr/local/bin/setup-ollama-permissions.sh

# Copy systemd service files
echo "Setting up systemd services..."
sudo cp dev_build/systemd/setup-instance-store.service /etc/systemd/system/
sudo cp dev_build/systemd/ollama-permissions.service /etc/systemd/system/

# Reload systemd and enable services
sudo systemctl daemon-reload
sudo systemctl enable setup-instance-store.service
sudo systemctl enable ollama-permissions.service

# Start instance store setup services
echo "Setting up instance store and permissions..."
sudo systemctl start setup-instance-store.service
sudo systemctl start ollama-permissions.service

# Fix TPM device permissions
echo "Setting up TPM device permissions..."
sudo chgrp tss /dev/tpm0 /dev/tpmrm0
sudo chmod 660 /dev/tpm0 /dev/tpmrm0

echo "Setup complete!"
echo ""
echo "To start the services:"
echo "  ./dev_build/start-services.sh"
echo ""
echo "To check status:"
echo "  sudo systemctl status ollama-backend"
echo "  sudo systemctl status ollama-frontend"
echo ""
echo "Frontend will be available at: http://localhost:3000"
echo "Backend API will be available at: http://localhost:8000"