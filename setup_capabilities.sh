#!/bin/bash

# Setup Packet Capture Capabilities
# This script sets up capabilities to allow packet capture without sudo

echo "=== Setting up Packet Capture Capabilities ==="
echo ""

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script needs to be run as root to set capabilities"
    echo "Usage: sudo ./setup_capabilities.sh"
    exit 1
fi

# Find the Python executable in the virtual environment
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

PYTHON_PATH="$VENV_PATH/bin/python3"

if [ ! -f "$PYTHON_PATH" ]; then
    echo "Python executable not found at: $PYTHON_PATH"
    exit 1
fi

echo "Found Python executable: $PYTHON_PATH"

# Install libcap2-bin if not available
if ! command -v setcap &> /dev/null; then
    echo "Installing libcap2-bin..."
    apt update
    apt install -y libcap2-bin
fi

# Set capabilities for packet capture
echo "Setting packet capture capabilities..."
setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH"

# Verify capabilities
echo "Verifying capabilities..."
getcap "$PYTHON_PATH"

echo ""
echo "=== Capabilities Setup Complete ==="
echo "You can now run the WiFi scanner without sudo:"
echo "  python3 wifi_scanner.py"
echo ""
echo "Note: If you still get permission errors, you may need to run with sudo:"
echo "  ./run_with_sudo.sh"
