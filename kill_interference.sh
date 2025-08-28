#!/bin/bash

# Kill Interfering Processes Script
# This script kills processes that interfere with WiFi monitor mode

echo "=== Killing Interfering Processes ==="
echo ""

echo "Checking for interfering processes..."
sudo airmon-ng check

echo ""
echo "Killing interfering processes..."
sudo airmon-ng check kill

echo ""
echo "Checking again after killing processes..."
sudo airmon-ng check

echo ""
echo "Done! You can now try putting your interface in monitor mode."
echo "Usage: sudo airmon-ng start <interface_name>"
