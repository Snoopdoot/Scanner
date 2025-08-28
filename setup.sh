#!/bin/bash

# WiFi Scanner Setup Script for Kali Linux ARM64
# This script sets up the environment for the WiFi scanning program

set -e

echo "=== WiFi Scanner Setup for Kali Linux ARM64 ==="

# Check for ARM64 architecture
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "arm64" ]; then
    echo "Warning: This script is optimized for ARM64 architecture."
    echo "Current architecture: $ARCH"
    echo "Continue anyway? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 1
    fi
fi

# Check current directory and permissions
echo "Current working directory: $(pwd)"
echo "Directory permissions: $(ls -ld .)"
if [ ! -w . ]; then
    echo "ERROR: No write permission in current directory"
    echo "Please run this script from a directory where you have write permissions"
    echo "Suggested locations:"
    echo "  - /home/$USER/"
    echo "  - /tmp/"
    exit 1
fi

echo "Installing system dependencies..."

# Update package list
sudo apt update

# Install Kali metapackage for WiFi tools (includes aircrack-ng, kismet, etc.)
echo "Installing Kali WiFi tools metapackage..."
sudo apt install -y kali-tools-802-11

# Install additional required system packages
# Note: aircrack-ng provides airmon-ng, airodump-ng, and other WiFi tools
# iw is the modern replacement for iwconfig
# tcpdump for packet capture capabilities
echo "Installing additional system dependencies..."
sudo apt install -y \
    iw \
    tcpdump \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpcap-dev \
    libffi-dev \
    libssl-dev

echo "Creating Python virtual environment..."

# Remove existing venv if it exists and has permission issues
if [ -d "venv" ]; then
    echo "Removing existing virtual environment..."
    rm -rf venv
fi

# Create virtual environment with proper error handling
if ! python3 -m venv venv; then
    echo "ERROR: Failed to create virtual environment"
    echo "This might be due to permission issues or insufficient disk space"
    echo "Current directory: $(pwd)"
    echo "Available space: $(df -h . | tail -1 | awk '{print $4}')"
    echo "Permissions: $(ls -ld .)"
    exit 1
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing Python requirements..."
pip install -r requirements.txt

echo "Setting up permissions for WiFi monitoring..."
# Create a udev rule to allow non-root access to WiFi devices
sudo tee /etc/udev/rules.d/99-wifi-monitor.rules > /dev/null <<EOF
# Allow users in the netdev group to access WiFi devices
SUBSYSTEM=="net", KERNEL=="wlan*", GROUP="netdev", MODE="0660"
EOF

# Add current user to netdev group if it exists, otherwise create it
if ! getent group netdev > /dev/null 2>&1; then
    sudo groupadd netdev
fi
sudo usermod -a -G netdev $USER

echo "Reloading udev rules..."
sudo udevadm control --reload-rules
sudo udevadm trigger

# Validate installation
echo ""
echo "=== Validating Installation ==="
echo "Checking for critical tools..."

# Check for aircrack-ng tools
if ! command -v aircrack-ng &> /dev/null; then
    echo "ERROR: aircrack-ng could not be found"
    exit 1
else
    echo "✓ aircrack-ng found"
fi

if ! command -v airmon-ng &> /dev/null; then
    echo "ERROR: airmon-ng could not be found"
    exit 1
else
    echo "✓ airmon-ng found"
fi

# Check for iw (modern replacement for iwconfig)
if ! command -v iw &> /dev/null; then
    echo "ERROR: iw could not be found"
    exit 1
else
    echo "✓ iw found"
fi

# Check for tcpdump
if ! command -v tcpdump &> /dev/null; then
    echo "ERROR: tcpdump could not be found"
    exit 1
else
    echo "✓ tcpdump found"
fi

# Check Python environment
if ! python3 -c "import flask, scapy, netifaces, psutil" 2>/dev/null; then
    echo "ERROR: Some Python packages are missing"
    exit 1
else
    echo "✓ Python packages verified"
fi

# Check for WiFi interfaces
echo ""
echo "=== WiFi Interface Check ==="
WIFI_INTERFACES=$(iw dev | grep -E "Interface|wlan" | grep -v "Interface" | awk '{print $2}' | tr '\n' ' ')
if [ -z "$WIFI_INTERFACES" ]; then
    echo "Warning: No WiFi interfaces detected"
    echo "Make sure your WiFi card is properly connected"
else
    echo "✓ WiFi interfaces found: $WIFI_INTERFACES"
fi

echo ""
echo "=== Setup Complete ==="
echo "All tools installed and validated successfully!"
echo ""
echo "To run the WiFi scanner:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the scanner: python3 wifi_scanner.py"
echo "3. Open your browser to: http://localhost:5000"
echo ""
echo "Note: You may need to log out and back in for group changes to take effect."
echo "To put a WiFi interface in monitor mode:"
echo "  sudo airmon-ng start <interface_name>"
