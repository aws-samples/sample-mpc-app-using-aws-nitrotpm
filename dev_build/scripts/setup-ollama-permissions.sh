#!/bin/bash
set -e

# Create models directory and set permissions
mkdir -p /mnt/instance-store/models
chown -R ollama:ollama /mnt/instance-store/models
chmod 775 /mnt/instance-store/models

# Add ec2-user to necessary groups for backend service access
usermod -a -G ollama,tss ec2-user

echo "Write out the modelfile"
cat > /mnt/instance-store/modelfile << 'EOF'
FROM /mnt/instance-store/llama2-7b.gguf
TEMPLATE """
<s>[INST] {{ .Prompt }} [/INST] 
"""
EOF
chown ollama:ollama /mnt/instance-store/modelfile
chmod 755 /mnt/instance-store/modelfile