#!/bin/bash

# Run WiFi Scanner with Sudo Privileges
# This script runs the WiFi scanner with proper permissions for packet capture

echo "=== WiFi Scanner with Sudo Privileges ==="
echo ""

# Check if virtual environment exists
VENV_FOUND=false

# Check current directory
if [ -d "venv" ]; then
    VENV_PATH="venv"
    VENV_FOUND=true
fi

# Check home directory (alternative setup)
if [ -d "$HOME/.venv-wifi-scanner" ]; then
    VENV_PATH="$HOME/.venv-wifi-scanner"
    VENV_FOUND=true
fi

if [ "$VENV_FOUND" = false ]; then
    echo "Virtual environment not found. Please run setup.sh or setup_alt.sh first."
    echo "Usage: ./setup.sh or ./setup_alt.sh"
    exit 1
fi

echo "Using virtual environment: $VENV_PATH"

# Check if we're already running as root
if [ "$EUID" -eq 0 ]; then
    echo "Already running as root"
    PYTHON_PATH="$VENV_PATH/bin/python3"
else
    echo "Running with sudo privileges for packet capture..."
    PYTHON_PATH="sudo $VENV_PATH/bin/python3"
fi

# Check if required files exist
if [ ! -f "wifi_scanner.py" ]; then
    echo "Error: wifi_scanner.py not found in current directory"
    exit 1
fi

if [ ! -f "templates/index.html" ]; then
    echo "Error: Web interface template not found"
    exit 1
fi

echo "Starting WiFi Scanner with proper permissions..."
echo "Web interface will be available at: http://localhost:5000"
echo "Press Ctrl+C to stop the scanner"
echo ""

# Run the WiFi scanner with sudo
$PYTHON_PATH wifi_scanner.py
