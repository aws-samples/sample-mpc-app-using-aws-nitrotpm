#!/bin/bash

echo "Starting Ollama Chat Interface services..."

# Start backend
echo "Starting backend service..."
sudo systemctl start ollama-backend

# Wait a moment for backend to start
sleep 2

# Start frontend
echo "Starting frontend service..."
sudo systemctl start ollama-frontend

echo ""
echo "Services started!"
echo "Backend status:"
sudo systemctl status ollama-backend --no-pager -l
echo ""
echo "Frontend status:"
sudo systemctl status ollama-frontend --no-pager -l
echo ""
echo "Access the application at: http://localhost:3000"