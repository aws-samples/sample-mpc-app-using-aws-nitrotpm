#!/bin/bash

echo "Stopping Ollama Chat Interface services..."

# Stop services
sudo systemctl stop ollama-frontend
sudo systemctl stop ollama-backend

echo "Services stopped!"
echo ""
echo "Backend status:"
sudo systemctl status ollama-backend --no-pager -l
echo ""
echo "Frontend status:"
sudo systemctl status ollama-frontend --no-pager -l