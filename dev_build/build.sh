#!/bin/bash


echo "Setting up Ollama Chat Interface..."



# Install Python dependencies
echo "Installing Python dependencies..."
cd ./backend
pip3 install --user -r requirements.txt
cd ..

# Install Node.js dependencies and build frontend
echo "Installing Node.js dependencies..."
cd ./frontend
npm install
echo "Building React frontend..."
npm run build
echo "Build directory contents:"
ls -la build/ || echo "Build directory not found"
cd ..


# Copy systemd service files
echo "Setting up systemd services..."
sudo cp dev_build/systemd/ollama-backend.service /etc/systemd/system/
sudo cp dev_build/systemd/ollama-frontend.service /etc/systemd/system/

# Reload systemd and enable services
sudo systemctl daemon-reload
sudo systemctl enable ollama-backend.service
sudo systemctl enable ollama-frontend.service


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