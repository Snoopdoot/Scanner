#!/bin/bash

# WiFi Scanner Launcher Script
# This script activates the virtual environment and runs the WiFi scanner

echo "=== WiFi Scanner Launcher ==="

# Check for virtual environment in different locations
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

# Check if we're in the virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Activating virtual environment from: $VENV_PATH"
    source "$VENV_PATH/bin/activate"
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

echo "Starting WiFi Scanner..."
echo "Web interface will be available at: http://localhost:5000"
echo "Press Ctrl+C to stop the scanner"
echo ""

# Run the WiFi scanner
python3 wifi_scanner.py
