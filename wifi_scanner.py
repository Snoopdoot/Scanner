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
        self.ghost_mode = True
        self.filter_multicast = True
        self.persistence_minutes = 1 # Default persistence
        
    def find_wifi_interfaces(self):
        """Find available WiFi interfaces"""
        interfaces = []
        try:
            all_interfaces = netifaces.interfaces()
            print(f"All network interfaces: {all_interfaces}")
            
            for iface in all_interfaces:
                if iface.startswith('wlan') or iface.startswith('wifi'):
                    if not iface.endswith('mon') and not self._is_interface_in_monitor_mode(iface):
                        interfaces.append(iface)
                        print(f"Found WiFi interface: {iface}")
            
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
            
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True, text=True)
            subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True, text=True)
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True, text=True)
            
            if result.returncode == 0:
                current_interfaces = netifaces.interfaces()
                monitor_interfaces = [iface for iface in current_interfaces if 'mon' in iface]
                if monitor_interfaces:
                    self.monitor_interface = monitor_interfaces[0]
                    print(f"Using monitor interface: {self.monitor_interface}")
                    return True
                if self._is_interface_in_monitor_mode(interface):
                    self.monitor_interface = interface
                    return True
                print("No monitor interface found")
                return False
            return False
        except Exception as e:
            print(f"Error putting interface in monitor mode: {e}")
            return False
    
    def packet_handler(self, packet):
        """Handle captured WiFi packets"""
        try:
            if not packet.haslayer(Dot11):
                return

            current_time = datetime.now()

            # Handle Access Points (Beacon frames) - Not subject to multicast filtering
            if packet.haslayer(Dot11Beacon):
                bssid = packet.addr3
                if bssid and bssid != "ff:ff:ff:ff:ff:ff":
                    ssid = ""
                    try:
                        if hasattr(packet[Dot11Elt], 'info'):
                            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except Exception:
                        ssid = "<hidden>"

                    channel = 0
                    try:
                        channel = int(ord(packet[Dot11Elt:3].info))
                    except Exception:
                        pass
                    
                    if bssid not in self.access_points:
                        self.access_points[bssid] = {'bssid': bssid, 'packet_count': 0}

                    self.access_points[bssid].update({
                        'ssid': ssid,
                        'channel': channel,
                        'signal_strength': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100,
                        'last_seen': current_time.isoformat(),
                        'packet_count': self.access_points[bssid].get('packet_count', 0) + 1,
                        'state': 'active'
                    })
                    self.last_seen[bssid] = current_time

            # Handle clients and connections using data frames
            elif packet.type == 2:
                ds = packet.FCfield & 0x3
                to_ds = ds & 0x1 != 0
                from_ds = ds & 0x2 != 0

                if to_ds and not from_ds:
                    ap_bssid = packet.addr1
                    client_mac = packet.addr2
                elif not to_ds and from_ds:
                    client_mac = packet.addr1
                    ap_bssid = packet.addr2
                else:
                    return

                # Correctly apply the filter ONLY to the identified client MAC
                if self.filter_multicast and (client_mac.startswith("33:33:") or client_mac == "ff:ff:ff:ff:ff:ff"):
                    return

                if ap_bssid in self.access_points and client_mac:
                    is_broadcast = client_mac == "ff:ff:ff:ff:ff:ff"

                    if client_mac in self.clients and self.clients[client_mac].get('bssid') != ap_bssid and not is_broadcast:
                        old_bssid = self.clients[client_mac].get('bssid')
                        if (old_bssid, client_mac) in self.connections:
                            del self.connections[(old_bssid, client_mac)]

                    if client_mac not in self.clients:
                        client_type = "broadcast" if is_broadcast else "client"
                        self.clients[client_mac] = {'mac': client_mac, 'packet_count': 0, 'type': client_type}
                    
                    self.clients[client_mac]['last_seen'] = current_time.isoformat()
                    self.clients[client_mac]['packet_count'] += 1
                    self.clients[client_mac]['state'] = 'active'
                    if not is_broadcast:
                        self.clients[client_mac]['bssid'] = ap_bssid
                    self.last_seen[client_mac] = current_time

                    connection_key = (ap_bssid, client_mac)
                    if connection_key not in self.connections:
                        self.connections[connection_key] = {
                            'ap_bssid': ap_bssid,
                            'client_mac': client_mac,
                            'packet_count': 0,
                            'direction': 'unknown'
                        }
                    
                    self.connections[connection_key]['packet_count'] += 1
                    self.connections[connection_key]['last_seen'] = current_time.isoformat()
                    self.packet_counts[connection_key] += 1
                    
                    direction = 'client_to_ap' if to_ds else 'ap_to_client'
                    if self.connections[connection_key]['direction'] not in ('bidirectional', direction):
                        self.connections[connection_key]['direction'] = 'bidirectional' if self.connections[connection_key]['direction'] != 'unknown' else direction
        except Exception as e:
            pass
    
    def cleanup_old_entries(self):
        """Manage device states: active -> ghost -> removed"""
        now = datetime.now()
        remove_time = now - timedelta(minutes=self.persistence_minutes)
        ghost_time = remove_time + timedelta(seconds=30) # Ghost period is last 30s of persistence

        for bssid, ap in list(self.access_points.items()):
            last_seen_dt = datetime.fromisoformat(ap['last_seen'])
            if last_seen_dt < remove_time:
                del self.access_points[bssid]
            elif self.ghost_mode and last_seen_dt < ghost_time:
                self.access_points[bssid]['state'] = 'ghost'

        for mac, client in list(self.clients.items()):
            last_seen_dt = datetime.fromisoformat(client['last_seen'])
            if last_seen_dt < remove_time:
                del self.clients[mac]
            elif self.ghost_mode and last_seen_dt < ghost_time:
                self.clients[mac]['state'] = 'ghost'

        self.connections = {k: v for k, v in self.connections.items() if k[0] in self.access_points and k[1] in self.clients}

    def start_scanning(self, interface):
        """Start WiFi scanning on specified interface"""
        self.interface = interface
        if not self.put_interface_in_monitor_mode(interface):
            return False
        
        self.scanning = True
        
        def scan_thread():
            try:
                sniff(iface=self.monitor_interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.scanning)
            except Exception as e:
                print(f"Error in scanning thread: {e}")
                self.scanning = False
        
        def channel_hopper_thread():
            # Expanded 2.4GHz and 5GHz channels
            channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
            while self.scanning:
                for channel in channels:
                    if not self.scanning:
                        break
                    try:
                        subprocess.run(['sudo', 'iwconfig', self.monitor_interface, 'channel', str(channel)],
                                     capture_output=True, text=True)
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"Error hopping channels: {e}")
                        break

        def cleanup_thread():
            while self.scanning:
                self.cleanup_old_entries()
                time.sleep(10)
        
        threading.Thread(target=scan_thread, daemon=True).start()
        threading.Thread(target=channel_hopper_thread, daemon=True).start()
        threading.Thread(target=cleanup_thread, daemon=True).start()
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
        
        # Dynamically filter clients if the toggle is on
        clients_to_send = self.clients.copy()
        if self.filter_multicast:
            clients_to_send = {mac: client for mac, client in clients_to_send.items() if not (mac.startswith("33:33:") or mac == "ff:ff:ff:ff:ff:ff")}

        connections_to_send = {k: v for k, v in self.connections.items() if k[1] in clients_to_send}


        connections_with_thickness = []
        for conn in connections_to_send.values():
            new_conn = conn.copy()
            packet_count = new_conn.get('packet_count', 0)
            thickness = min(10, max(1, packet_count // 10))
            new_conn['thickness'] = thickness
            connections_with_thickness.append(new_conn)

        return {
            'access_points': list(self.access_points.values()),
            'clients': list(clients_to_send.values()),
            'connections': connections_with_thickness
        }

scanner = WiFiScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces')
def get_interfaces():
    interfaces = scanner.find_wifi_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    interface = request.json.get('interface')
    if not interface:
        return jsonify({'error': 'No interface specified'}), 400
    if scanner.scanning:
        return jsonify({'error': 'Already scanning'}), 400
    if scanner.start_scanning(interface):
        return jsonify({'message': f'Started scanning on {interface}'})
    else:
        return jsonify({'error': f'Failed to start scanning on {interface}'}), 500

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    scanner.stop_scanning()
    return jsonify({'message': 'Scanning stopped'})

@socketio.on('connect')
def handle_connect():
    emit('status', {'message': 'Connected to WiFi Scanner'})

@socketio.on('update_settings')
def handle_settings_update(data):
    scanner.ghost_mode = data.get('ghostMode', True)
    scanner.filter_multicast = data.get('filterMulticast', True)
    scanner.persistence_minutes = data.get('persistence', 1)

def broadcast_updates():
    """Broadcast network updates to connected clients"""
    while True:
        if scanner.scanning:
            data = scanner.get_network_data()
            socketio.emit('network_update', data)
        time.sleep(2)

if __name__ == '__main__':
    threading.Thread(target=broadcast_updates, daemon=True).start()
    print("WiFi Scanner starting... Open your browser to: http://localhost:5000")
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        scanner.stop_scanning()