#!/bin/bash

# Virtual Environment Fix Script
# This script helps resolve virtual environment creation issues

echo "=== Virtual Environment Fix Script ==="
echo ""

# Check current directory
echo "Current directory: $(pwd)"
echo "Directory permissions: $(ls -ld .)"
echo ""

# Check if we're on a mounted filesystem
FILESYSTEM=$(df . | tail -1 | awk '{print $1}')
echo "Filesystem: $FILESYSTEM"

if [[ "$FILESYSTEM" == *"media"* ]] || [[ "$FILESYSTEM" == *"mnt"* ]]; then
    echo "⚠ Warning: You're on a mounted filesystem"
    echo "This can cause permission issues with virtual environments"
    echo ""
    echo "Suggested solutions:"
    echo "1. Copy the project to a local directory:"
    echo "   cp -r . /home/$USER/wifi-scanner/"
    echo "   cd /home/$USER/wifi-scanner/"
    echo "   ./setup.sh"
    echo ""
    echo "2. Or use a different location for the virtual environment:"
    echo "   export VIRTUAL_ENV_PATH=/home/$USER/.venv-wifi-scanner"
    echo "   python3 -m venv \$VIRTUAL_ENV_PATH"
    echo ""
fi

# Check available space
echo "Available disk space:"
df -h . | tail -1
echo ""

# Check Python version and venv module
echo "Python version: $(python3 --version)"
if python3 -c "import venv" 2>/dev/null; then
    echo "✓ venv module available"
else
    echo "✗ venv module not available"
    echo "Installing python3-venv..."
    sudo apt update
    sudo apt install -y python3-venv
fi
echo ""

# Try to create venv in different locations
echo "=== Testing Virtual Environment Creation ==="

# Test 1: Current directory
echo "Test 1: Creating venv in current directory..."
if python3 -m venv test_venv 2>/dev/null; then
    echo "✓ Success in current directory"
    rm -rf test_venv
else
    echo "✗ Failed in current directory"
fi

# Test 2: Home directory
echo "Test 2: Creating venv in home directory..."
if python3 -m venv ~/test_venv 2>/dev/null; then
    echo "✓ Success in home directory"
    rm -rf ~/test_venv
else
    echo "✗ Failed in home directory"
fi

# Test 3: /tmp directory
echo "Test 3: Creating venv in /tmp directory..."
if python3 -m venv /tmp/test_venv 2>/dev/null; then
    echo "✓ Success in /tmp directory"
    rm -rf /tmp/test_venv
else
    echo "✗ Failed in /tmp directory"
fi

echo ""
echo "=== Recommended Solutions ==="

if [[ "$FILESYSTEM" == *"media"* ]] || [[ "$FILESYSTEM" == *"mnt"* ]]; then
    echo "1. MOVE PROJECT TO LOCAL DIRECTORY:"
    echo "   mkdir -p /home/$USER/wifi-scanner"
    echo "   cp -r . /home/$USER/wifi-scanner/"
    echo "   cd /home/$USER/wifi-scanner"
    echo "   ./setup.sh"
    echo ""
    echo "2. OR USE ALTERNATIVE VENV LOCATION:"
    echo "   # Edit setup.sh to use a different venv path"
    echo "   # Change 'python3 -m venv venv' to:"
    echo "   # python3 -m venv /home/$USER/.venv-wifi-scanner"
    echo "   # And update the activation path accordingly"
else
    echo "1. CHECK PERMISSIONS:"
    echo "   sudo chown -R $USER:$USER ."
    echo "   chmod -R 755 ."
    echo ""
    echo "2. CLEAN UP AND RETRY:"
    echo "   rm -rf venv"
    echo "   ./setup.sh"
fi

echo ""
echo "3. MANUAL VENV CREATION:"
echo "   python3 -m venv /home/$USER/.venv-wifi-scanner"
echo "   source /home/$USER/.venv-wifi-scanner/bin/activate"
echo "   pip install -r requirements.txt"
echo ""
