#!/bin/bash

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or use sudo!"
  exit 1
fi

# Check if Python is installed
echo "Checking for Python installation..."
if ! command -v python3 &> /dev/null; then
  echo "Python3 is not installed. Please install Python3 before running this script!"
  exit 1
fi

# Create a virtual environment
echo "Creating virtual environment..."
python3 -m venv .venv

# Activate the virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install required libraries from requirements.txt
echo "Installing required libraries..."
pip install -r requirements.txt

echo "Installation complete! You can run the application using: 'python3 traffic_detector.py'"