#!/bin/bash

# Check Interface Mode Script
# This script checks the current mode of WiFi interfaces

echo "=== WiFi Interface Mode Check ==="
echo ""

# List all network interfaces
echo "All network interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'
echo ""

# Check WiFi interfaces specifically
echo "WiFi interfaces and their modes:"
for interface in $(ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://' | grep -E "wlan|wifi"); do
    echo "Interface: $interface"
    
    # Check if interface exists
    if [ -d "/sys/class/net/$interface" ]; then
        echo "  Status: ✓ Exists"
        
        # Check interface mode using iw
        if command -v iw >/dev/null 2>&1; then
            iw_output=$(iw dev "$interface" info 2>/dev/null)
            if echo "$iw_output" | grep -q "type monitor"; then
                echo "  Mode: Monitor"
            elif echo "$iw_output" | grep -q "type managed"; then
                echo "  Mode: Managed"
            else
                echo "  Mode: Unknown"
            fi
        else
            echo "  Mode: Cannot check (iw not available)"
        fi
        
        # Check if interface is up
        if ip link show "$interface" | grep -q "UP"; then
            echo "  State: UP"
        else
            echo "  State: DOWN"
        fi
    else
        echo "  Status: ✗ Does not exist"
    fi
    echo ""
done

echo "=== airmon-ng status ==="
if command -v airmon-ng >/dev/null 2>&1; then
    airmon-ng
else
    echo "airmon-ng not available"
fi
