#!/usr/bin/env python3
"""
Test script to check WiFi interface detection and monitor mode setup
"""

import netifaces
import subprocess
import sys

def test_interface_detection():
    """Test WiFi interface detection"""
    print("=== Testing WiFi Interface Detection ===")
    
    try:
        all_interfaces = netifaces.interfaces()
        print(f"All network interfaces: {all_interfaces}")
        
        wifi_interfaces = []
        for iface in all_interfaces:
            if iface.startswith('wlan') or iface.startswith('wifi'):
                wifi_interfaces.append(iface)
                print(f"Found WiFi interface: {iface}")
        
        print(f"Total WiFi interfaces found: {len(wifi_interfaces)}")
        return wifi_interfaces
        
    except Exception as e:
        print(f"Error finding WiFi interfaces: {e}")
        return []

def test_airmon_ng():
    """Test airmon-ng availability"""
    print("\n=== Testing airmon-ng ===")
    
    try:
        result = subprocess.run(['which', 'airmon-ng'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ airmon-ng found at: {result.stdout.strip()}")
            return True
        else:
            print("✗ airmon-ng not found")
            return False
    except Exception as e:
        print(f"Error checking airmon-ng: {e}")
        return False

def test_interface_monitor_mode(interface):
    """Test putting an interface in monitor mode"""
    print(f"\n=== Testing Monitor Mode for {interface} ===")
    
    try:
        # Check if interface exists
        if interface not in netifaces.interfaces():
            print(f"✗ Interface {interface} not found")
            return False
        
        print(f"✓ Interface {interface} exists")
        
        # Kill interfering processes first
        print("Killing interfering processes...")
        kill_result = subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                                   capture_output=True, text=True)
        print(f"Kill command output: {kill_result.stdout}")
        
        # Test airmon-ng start
        print(f"Testing airmon-ng start {interface}...")
        result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                              capture_output=True, text=True)
        
        print(f"Return code: {result.returncode}")
        print(f"Output: {result.stdout}")
        if result.stderr:
            print(f"Errors: {result.stderr}")
        
        if result.returncode == 0:
            print(f"✓ Successfully started monitor mode for {interface}")
            
            # Check for monitor interface
            all_interfaces = netifaces.interfaces()
            monitor_interfaces = [iface for iface in all_interfaces if 'mon' in iface]
            print(f"Monitor interfaces found: {monitor_interfaces}")
            
            # Check if original interface is in monitor mode
            try:
                iw_result = subprocess.run(['iw', 'dev', interface, 'info'], 
                                         capture_output=True, text=True)
                if 'type monitor' in iw_result.stdout.lower():
                    print(f"✓ Original interface {interface} is in monitor mode")
                else:
                    print(f"⚠ Original interface {interface} is not in monitor mode")
            except Exception as e:
                print(f"Error checking interface mode: {e}")
            
            # Stop monitor mode
            print(f"Stopping monitor mode for {interface}...")
            subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                         capture_output=True, text=True)
            
            return True
        else:
            print(f"✗ Failed to start monitor mode for {interface}")
            return False
            
    except Exception as e:
        print(f"Error testing monitor mode: {e}")
        return False

def main():
    """Main test function"""
    print("WiFi Interface Test Script")
    print("=" * 50)
    
    # Test interface detection
    wifi_interfaces = test_interface_detection()
    
    # Test airmon-ng
    airmon_available = test_airmon_ng()
    
    if not wifi_interfaces:
        print("\n❌ No WiFi interfaces found!")
        print("Make sure your WiFi card is properly connected and detected.")
        sys.exit(1)
    
    if not airmon_available:
        print("\n❌ airmon-ng not available!")
        print("Make sure aircrack-ng is installed: sudo apt install aircrack-ng")
        sys.exit(1)
    
    # Test monitor mode for first interface
    if wifi_interfaces:
        test_interface_monitor_mode(wifi_interfaces[0])
    
    print("\n✅ Test completed!")
    print(f"Available WiFi interfaces: {wifi_interfaces}")

if __name__ == "__main__":
    main()
