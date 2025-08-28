#!/usr/bin/env python3
"""
WiFi Scanner with Real-time Web Interface
Scans WiFi networks in monitor mode and displays AP-client relationships
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
import netifaces
import psutil

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Deauth

# Suppress Scapy warnings
conf.verb = 0

app = Flask(__name__)
app.config['SECRET_KEY'] = 'wifi_scanner_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

class WiFiScanner:
    def __init__(self):
        self.access_points = {}  # BSSID -> AP info
        self.clients = {}        # MAC -> Client info
        self.connections = {}    # (AP_BSSID, CLIENT_MAC) -> connection info
        self.packet_counts = defaultdict(int)  # Track packet counts for line thickness
        self.last_seen = {}      # Track last seen times
        self.scanning = False
        self.interface = None
        self.monitor_interface = None
        
    def find_wifi_interfaces(self):
        """Find available WiFi interfaces"""
        interfaces = []
        try:
            all_interfaces = netifaces.interfaces()
            print(f"All network interfaces: {all_interfaces}")
            
            for iface in all_interfaces:
                if iface.startswith('wlan') or iface.startswith('wifi'):
                    # Don't include interfaces that are already in monitor mode
                    if not iface.endswith('mon'):
                        # Check if interface is in monitor mode using iw
                        if not self._is_interface_in_monitor_mode(iface):
                            interfaces.append(iface)
                            print(f"Found WiFi interface: {iface}")
                        else:
                            print(f"Skipping interface in monitor mode: {iface}")
                    else:
                        print(f"Skipping monitor interface: {iface}")
            
            print(f"Total WiFi interfaces found: {len(interfaces)}")
            return interfaces
        except Exception as e:
            print(f"Error finding WiFi interfaces: {e}")
            return []
    
    def _is_interface_in_monitor_mode(self, interface):
        """Check if an interface is in monitor mode"""
        try:
            result = subprocess.run(['iw', 'dev', interface, 'info'], 
                                  capture_output=True, text=True)
            return 'type monitor' in result.stdout.lower()
        except:
            return False
    
    def put_interface_in_monitor_mode(self, interface):
        """Put WiFi interface in monitor mode"""
        try:
            print(f"Attempting to put interface '{interface}' in monitor mode")
            
            # Kill interfering processes first
            print("Killing interfering processes...")
            kill_result = subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                                       capture_output=True, text=True)
            print(f"Kill command output: {kill_result.stdout}")
            if kill_result.stderr:
                print(f"Kill command errors: {kill_result.stderr}")
            
            # Stop any existing monitor interfaces
            print(f"Stopping any existing monitor interfaces for {interface}")
            stop_result = subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                                       capture_output=True, text=True)
            print(f"Stop command output: {stop_result.stdout}")
            if stop_result.stderr:
                print(f"Stop command errors: {stop_result.stderr}")
            
            # Start monitor mode
            print(f"Starting monitor mode for {interface}")
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                                  capture_output=True, text=True)
            
            print(f"Start command return code: {result.returncode}")
            print(f"Start command output: {result.stdout}")
            if result.stderr:
                print(f"Start command errors: {result.stderr}")
            
            if result.returncode == 0:
                # First, try to find the monitor interface in the current interfaces
                current_interfaces = netifaces.interfaces()
                print(f"Current interfaces after airmon-ng: {current_interfaces}")
                
                # Look for monitor interfaces (containing 'mon')
                monitor_interfaces = [iface for iface in current_interfaces if 'mon' in iface]
                print(f"Monitor interfaces found: {monitor_interfaces}")
                
                if monitor_interfaces:
                    # Use the first monitor interface found
                    self.monitor_interface = monitor_interfaces[0]
                    print(f"Using monitor interface: {self.monitor_interface}")
                    return True
                
                # Check if the original interface is now in monitor mode
                # Some cards don't create separate monitor interfaces
                if interface in current_interfaces:
                    # Verify it's in monitor mode by checking with iw
                    try:
                        iw_result = subprocess.run(['iw', 'dev', interface, 'info'], 
                                                 capture_output=True, text=True)
                        if 'type monitor' in iw_result.stdout.lower():
                            self.monitor_interface = interface
                            print(f"Original interface {interface} is in monitor mode")
                            return True
                    except Exception as e:
                        print(f"Error checking interface mode: {e}")
                
                # Fallback: try common naming patterns
                print("Trying fallback naming patterns...")
                possible_names = [f"{interface}mon", f"{interface}mon0", f"{interface}0mon"]
                for name in possible_names:
                    if name in current_interfaces:
                        self.monitor_interface = name
                        print(f"Found monitor interface using fallback: {self.monitor_interface}")
                        return True
                
                print("No monitor interface found")
                return False
            else:
                print(f"airmon-ng start failed with return code: {result.returncode}")
                return False
                
        except Exception as e:
            print(f"Error putting interface in monitor mode: {e}")
            return False
    
    def packet_handler(self, packet):
        """Handle captured WiFi packets"""
        try:
            if not packet.haslayer(Dot11):
                return
                
            # Extract basic packet info
            if packet.haslayer(Dot11):
                src = packet[Dot11].addr2
                dst = packet[Dot11].addr1
                bssid = packet[Dot11].addr3
            
            current_time = datetime.now()
            
            # Handle Access Points (Beacon frames)
            if packet.haslayer(Dot11Beacon):
                if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                    ssid = ""
                    if packet.haslayer(Dot11Elt):
                        for layer in packet[Dot11Elt]:
                            if layer.ID == 0:  # SSID
                                try:
                                    ssid = layer.info.decode('utf-8', errors='ignore')
                                    break
                                except:
                                    ssid = "Unknown"
                    
                    # Get existing packet count or default to 0
                    existing_packet_count = 0
                    if bssid in self.access_points:
                        existing_packet_count = self.access_points[bssid].get('packet_count', 0)
                    
                    # Get channel safely
                    channel = 0
                    try:
                        if hasattr(packet[Dot11Beacon], 'network_stats') and packet[Dot11Beacon].network_stats:
                            channel = packet[Dot11Beacon].network_stats.get('channel', 0)
                    except:
                        channel = 0
                    
                    self.access_points[bssid] = {
                        'bssid': bssid,
                        'ssid': ssid,
                        'channel': channel,
                        'signal_strength': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 0,
                        'last_seen': current_time.isoformat(),
                        'packet_count': existing_packet_count + 1
                    }
                    self.last_seen[bssid] = current_time
            
            # Handle Clients (Probe requests, associations, etc.)
            if (packet.haslayer(Dot11ProbeReq) or 
                packet.haslayer(Dot11AssoReq) or 
                packet.haslayer(Dot11Auth)):
                
                if src and src != "ff:ff:ff:ff:ff:ff" and src != bssid:
                    # This is a client
                    # Get existing packet count or default to 0
                    existing_packet_count = 0
                    if src in self.clients:
                        existing_packet_count = self.clients[src].get('packet_count', 0)
                    
                    self.clients[src] = {
                        'mac': src,
                        'last_seen': current_time.isoformat(),
                        'packet_count': existing_packet_count + 1
                    }
                    self.last_seen[src] = current_time
                    
                    # Create connection if we have a BSSID
                    if bssid and bssid in self.access_points:
                        connection_key = (bssid, src)
                        # Get existing packet count or default to 0
                        existing_packet_count = 0
                        if connection_key in self.connections:
                            existing_packet_count = self.connections[connection_key].get('packet_count', 0)
                        
                        self.connections[connection_key] = {
                            'ap_bssid': bssid,
                            'client_mac': src,
                            'last_seen': current_time.isoformat(),
                            'packet_count': existing_packet_count + 1,
                            'direction': 'client_to_ap' if packet.haslayer(Dot11ProbeReq) else 'bidirectional'
                        }
                        self.packet_counts[connection_key] += 1
            
                                # Handle AP responses to clients
                    if (packet.haslayer(Dot11ProbeResp) or 
                        packet.haslayer(Dot11AssoResp)):
                        
                        if dst and dst != "ff:ff:ff:ff:ff:ff":
                            # This is a client receiving from AP
                            if dst in self.clients:
                                connection_key = (bssid, dst)
                                if connection_key in self.connections:
                                    self.connections[connection_key]['packet_count'] += 1
                                    self.connections[connection_key]['direction'] = 'bidirectional'
                                    self.packet_counts[connection_key] += 1
        except Exception as e:
            # Silently handle packet processing errors to avoid crashing the scanner
            pass
    
    def cleanup_old_entries(self):
        """Remove entries that haven't been seen for 1 minute"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(minutes=1)
        
        # Clean up access points
        ap_keys_to_remove = []
        for bssid, last_seen in self.last_seen.items():
            if bssid in self.access_points and last_seen < cutoff_time:
                ap_keys_to_remove.append(bssid)
        
        for bssid in ap_keys_to_remove:
            del self.access_points[bssid]
            del self.last_seen[bssid]
        
        # Clean up clients
        client_keys_to_remove = []
        for mac, last_seen in self.last_seen.items():
            if mac in self.clients and last_seen < cutoff_time:
                client_keys_to_remove.append(mac)
        
        for mac in client_keys_to_remove:
            del self.clients[mac]
            del self.last_seen[mac]
        
        # Clean up connections
        connection_keys_to_remove = []
        for (ap_bssid, client_mac), connection in self.connections.items():
            last_seen = datetime.fromisoformat(connection['last_seen'])
            if last_seen < cutoff_time:
                connection_keys_to_remove.append((ap_bssid, client_mac))
        
        for key in connection_keys_to_remove:
            del self.connections[key]
            if key in self.packet_counts:
                del self.packet_counts[key]
    
    def start_scanning(self, interface):
        """Start WiFi scanning on specified interface"""
        self.interface = interface
        
        if not self.put_interface_in_monitor_mode(interface):
            print(f"Failed to put {interface} in monitor mode")
            return False
        
        self.scanning = True
        
        def scan_thread():
            try:
                print(f"Starting WiFi scan on {self.monitor_interface}")
                # Try to run sniff with elevated privileges
                sniff(iface=self.monitor_interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.scanning)
            except PermissionError as e:
                print(f"Permission error in scanning thread: {e}")
                print("This usually means the interface needs elevated privileges")
                print("Try running the script with sudo or ensure proper permissions")
                self.scanning = False
            except Exception as e:
                print(f"Error in scanning thread: {e}")
                print(f"Error type: {type(e)}")
                import traceback
                traceback.print_exc()
                self.scanning = False
        
        def cleanup_thread():
            while self.scanning:
                self.cleanup_old_entries()
                time.sleep(10)  # Clean up every 10 seconds
        
        # Start scanning thread
        scan_thread_obj = threading.Thread(target=scan_thread, daemon=True)
        scan_thread_obj.start()
        
        # Start cleanup thread
        cleanup_thread_obj = threading.Thread(target=cleanup_thread, daemon=True)
        cleanup_thread_obj.start()
        
        return True
    
    def stop_scanning(self):
        """Stop WiFi scanning"""
        self.scanning = False
        if self.monitor_interface:
            try:
                subprocess.run(['sudo', 'airmon-ng', 'stop', self.monitor_interface], 
                             capture_output=True, text=True)
            except:
                pass
        self.monitor_interface = None
    
    def get_network_data(self):
        """Get current network data for web interface"""
        return {
            'access_points': list(self.access_points.values()),
            'clients': list(self.clients.values()),
            'connections': [
                {
                    'ap_bssid': conn['ap_bssid'],
                    'client_mac': conn['client_mac'],
                    'packet_count': conn['packet_count'],
                    'direction': conn['direction'],
                    'thickness': min(10, max(1, conn['packet_count'] // 10))  # Scale thickness
                }
                for conn in self.connections.values()
            ]
        }

# Global scanner instance
scanner = WiFiScanner()

@app.route('/')
def index():
    """Main web interface"""
    return render_template('index.html')

@app.route('/api/interfaces')
def get_interfaces():
    """Get available WiFi interfaces"""
    try:
        interfaces = scanner.find_wifi_interfaces()
        print(f"Found WiFi interfaces: {interfaces}")
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return jsonify({'interfaces': [], 'error': str(e)})

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Start WiFi scanning"""
    try:
        data = request.get_json()
        print(f"Received start_scan request with data: {data}")
        
        interface = data.get('interface')
        print(f"Interface from request: '{interface}'")
        
        if not interface:
            print("No interface specified in request")
            return jsonify({'error': 'No interface specified'}), 400
        
        if scanner.scanning:
            print("Scanner is already running")
            return jsonify({'error': 'Already scanning'}), 400
        
        print(f"Attempting to start scanning on interface: {interface}")
        success = scanner.start_scanning(interface)
        
        if success:
            print(f"Successfully started scanning on {interface}")
            return jsonify({'message': f'Started scanning on {interface}'})
        else:
            print(f"Failed to start scanning on {interface}")
            return jsonify({'error': f'Failed to start scanning on {interface}'}), 500
            
    except Exception as e:
        print(f"Error in start_scan endpoint: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    """Stop WiFi scanning"""
    scanner.stop_scanning()
    return jsonify({'message': 'Scanning stopped'})

@app.route('/api/network_data')
def get_network_data():
    """Get current network data"""
    return jsonify(scanner.get_network_data())

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('Client connected')
    emit('status', {'message': 'Connected to WiFi Scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('Client disconnected')

def broadcast_updates():
    """Broadcast network updates to connected clients"""
    while True:
        if scanner.scanning:
            try:
                data = scanner.get_network_data()
                print(f"Broadcasting network data: APs={len(data['access_points'])}, Clients={len(data['clients'])}, Connections={len(data['connections'])}")
                socketio.emit('network_update', data)
            except Exception as e:
                print(f"Error broadcasting updates: {e}")
                import traceback
                traceback.print_exc()
        time.sleep(2)  # Update every 2 seconds

if __name__ == '__main__':
    # Start broadcast thread
    broadcast_thread = threading.Thread(target=broadcast_updates, daemon=True)
    broadcast_thread.start()
    
    print("WiFi Scanner starting...")
    print("Open your browser to: http://localhost:5000")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\nShutting down...")
        scanner.stop_scanning()
    except Exception as e:
        print(f"Error: {e}")
        scanner.stop_scanning()
