#!/bin/bash

# WiFi Scanner Environment Validation Script
# This script validates that all required components are properly installed

set -e

echo "=== WiFi Scanner Environment Validation ==="
echo ""

# Check architecture
ARCH=$(dpkg --print-architecture)
echo "Architecture: $ARCH"
if [ "$ARCH" = "arm64" ]; then
    echo "✓ ARM64 architecture detected"
else
    echo "⚠ Warning: Not ARM64 architecture ($ARCH)"
fi
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "✓ Virtual environment found"
    
    # Check if virtual environment is activated
    if [ -z "$VIRTUAL_ENV" ]; then
        echo "⚠ Virtual environment not activated"
        echo "  Run: source venv/bin/activate"
    else
        echo "✓ Virtual environment activated"
    fi
else
    echo "✗ Virtual environment not found"
    echo "  Run: ./setup.sh"
    exit 1
fi
echo ""

# Check system tools
echo "=== System Tools ==="
TOOLS=("aircrack-ng" "airmon-ng" "iw" "tcpdump")
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool found"
    else
        echo "✗ $tool not found"
        MISSING_TOOLS=true
    fi
done
echo ""

# Check Python packages
echo "=== Python Packages ==="
PACKAGES=("flask" "flask_socketio" "scapy" "netifaces" "psutil" "eventlet")
for package in "${PACKAGES[@]}"; do
    if python3 -c "import $package" 2>/dev/null; then
        echo "✓ $package found"
    else
        echo "✗ $package not found"
        MISSING_PACKAGES=true
    fi
done
echo ""

# Check WiFi interfaces
echo "=== WiFi Interfaces ==="
WIFI_INTERFACES=$(iw dev 2>/dev/null | grep -E "Interface|wlan" | grep -v "Interface" | awk '{print $2}' | tr '\n' ' ')
if [ -z "$WIFI_INTERFACES" ]; then
    echo "⚠ No WiFi interfaces detected"
    echo "  Make sure your WiFi card is properly connected"
else
    echo "✓ WiFi interfaces found: $WIFI_INTERFACES"
fi
echo ""

# Check permissions
echo "=== Permissions ==="
if groups | grep -q netdev; then
    echo "✓ User is in netdev group"
else
    echo "⚠ User not in netdev group"
    echo "  You may need to log out and back in"
fi

if [ -f "/etc/udev/rules.d/99-wifi-monitor.rules" ]; then
    echo "✓ udev rules configured"
else
    echo "⚠ udev rules not found"
fi
echo ""

# Check application files
echo "=== Application Files ==="
FILES=("wifi_scanner.py" "templates/index.html" "requirements.txt")
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file found"
    else
        echo "✗ $file not found"
        MISSING_FILES=true
    fi
done
echo ""

# Summary
echo "=== Validation Summary ==="
if [ "$MISSING_TOOLS" = true ] || [ "$MISSING_PACKAGES" = true ] || [ "$MISSING_FILES" = true ]; then
    echo "✗ Validation failed - some components are missing"
    echo ""
    echo "To fix issues:"
    if [ "$MISSING_TOOLS" = true ]; then
        echo "  - Run: ./setup.sh (for missing system tools)"
    fi
    if [ "$MISSING_PACKAGES" = true ]; then
        echo "  - Activate virtual environment and run: pip install -r requirements.txt"
    fi
    if [ "$MISSING_FILES" = true ]; then
        echo "  - Ensure all project files are present"
    fi
    exit 1
else
    echo "✓ All components validated successfully!"
    echo ""
    echo "Ready to run WiFi scanner:"
    echo "  ./run.sh"
    echo "  or"
    echo "  source venv/bin/activate && python3 wifi_scanner.py"
fi
