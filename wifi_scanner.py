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

# Dictionary of known multicast MAC addresses and their labels
KNOWN_MULTICAST_MACS = {
    "ff:ff:ff:ff:ff:ff": "Broadcast",
    "01:80:c2:00:00:00": "Spanning Tree (STP)",
    "01:00:0c:cc:cc:cc": "Cisco Discovery (CDP)",
    "01:80:c2:00:00:0e": "Link Layer Discovery (LLDP)",
    "01:00:5e": "IPv4 Multicast",
    "33:33": "IPv6 Multicast"
}


class WiFiScanner:
    def __init__(self):
        self.access_points = {}  # BSSID -> AP info
        self.clients = {}        # MAC -> Client info
        self.connections = {}    # (AP_BSSID, CLIENT_MAC) -> connection info
        # --- MODIFIED: Use a deque to store (timestamp, size) tuples for the sliding window ---
        self.connection_traffic = defaultdict(deque)
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
            for iface in all_interfaces:
                if iface.startswith('wlan') or iface.startswith('wifi'):
                    if not iface.endswith('mon') and not self._is_interface_in_monitor_mode(iface):
                        interfaces.append(iface)
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
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True, text=True)
            subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True, text=True)
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True, text=True)

            if result.returncode == 0:
                current_interfaces = netifaces.interfaces()
                monitor_interfaces = [iface for iface in current_interfaces if 'mon' in iface]
                if monitor_interfaces:
                    self.monitor_interface = monitor_interfaces[0]
                    return True
                if self._is_interface_in_monitor_mode(interface):
                    self.monitor_interface = interface
                    return True
                return False
            return False
        except Exception as e:
            print(f"Error putting interface in monitor mode: {e}")
            return False
            
    def is_multicast(self, mac):
        """Check if a MAC address is a multicast address."""
        if not mac or len(mac.split(':')) != 6:
            return False
        first_octet = int(mac.split(':')[0], 16)
        return first_octet & 1

    def get_multicast_label(self, mac):
        """Get a descriptive label for a known multicast MAC address."""
        if mac in KNOWN_MULTICAST_MACS:
            return KNOWN_MULTICAST_MACS[mac]
        for prefix, label in KNOWN_MULTICAST_MACS.items():
            if mac.startswith(prefix):
                return label
        return "Multicast"

    def packet_handler(self, packet):
        """Handle captured WiFi packets"""
        try:
            if not packet.haslayer(Dot11):
                return

            current_time = datetime.now()
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -100
            packet_size = len(packet)

            if packet.haslayer(Dot11ProbeReq):
                client_mac = packet.addr2
                if client_mac and not self.is_multicast(client_mac):
                    if client_mac not in self.clients:
                        self.clients[client_mac] = {'mac': client_mac, 'packet_count': 0, 'type': 'client', 'probed_ssids': set()}
                    
                    ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    if ssid:
                        self.clients[client_mac]['probed_ssids'].add(ssid)
                    self.clients[client_mac]['last_seen'] = current_time.isoformat()
                    self.clients[client_mac]['signal_strength'] = signal_strength


            elif packet.haslayer(Dot11Beacon):
                bssid = packet.addr3
                if bssid and not self.is_multicast(bssid):
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
                        'signal_strength': signal_strength,
                        'last_seen': current_time.isoformat(),
                        'packet_count': self.access_points[bssid].get('packet_count', 0) + 1,
                        'state': 'active'
                    })

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

                is_multi = self.is_multicast(client_mac)

                if self.filter_multicast and is_multi:
                    return

                if ap_bssid in self.access_points and client_mac:
                    if client_mac in self.clients and self.clients[client_mac].get('bssid') and self.clients[client_mac].get('bssid') != ap_bssid:
                        old_bssid = self.clients[client_mac].get('bssid')
                        if (old_bssid, client_mac) in self.connections:
                            del self.connections[(old_bssid, client_mac)]

                    if client_mac not in self.clients:
                        client_type = "multicast" if is_multi else "client"
                        self.clients[client_mac] = {'mac': client_mac, 'packet_count': 0, 'type': client_type, 'probed_ssids': set()}
                        if is_multi:
                            self.clients[client_mac]['label'] = self.get_multicast_label(client_mac)
                    
                    self.clients[client_mac]['last_seen'] = current_time.isoformat()
                    self.clients[client_mac]['packet_count'] += 1
                    self.clients[client_mac]['state'] = 'active'
                    self.clients[client_mac]['bssid'] = ap_bssid
                    self.clients[client_mac]['signal_strength'] = signal_strength

                    connection_key = (ap_bssid, client_mac)
                    if connection_key not in self.connections:
                        self.connections[connection_key] = {
                            'ap_bssid': ap_bssid,
                            'client_mac': client_mac,
                        }
                    
                    self.connections[connection_key]['last_seen'] = current_time.isoformat()
                    # --- MODIFIED: Add (timestamp, size) to the deque ---
                    self.connection_traffic[connection_key].append((current_time, packet_size))

        except Exception:
            pass

    def cleanup_old_entries(self):
        now = datetime.now()
        remove_threshold = now - timedelta(minutes=self.persistence_minutes)

        for bssid, ap in list(self.access_points.items()):
            last_seen_dt = datetime.fromisoformat(ap['last_seen'])
            if last_seen_dt < remove_threshold:
                del self.access_points[bssid]
                continue
            if self.ghost_mode:
                ghost_threshold = now - timedelta(seconds=60)
                ap['state'] = 'ghost' if last_seen_dt < ghost_threshold else 'active'
            else:
                ap['state'] = 'active'
        
        for mac, client in list(self.clients.items()):
            last_seen_dt = datetime.fromisoformat(client['last_seen'])
            if last_seen_dt < remove_threshold:
                if mac in self.clients:
                    del self.clients[mac]
                continue
            if self.ghost_mode:
                ghost_threshold = now - timedelta(seconds=60)
                client['state'] = 'ghost' if last_seen_dt < ghost_threshold else 'active'
            else:
                client['state'] = 'active'

        self.connections = {k: v for k, v in self.connections.items() if k[0] in self.access_points and k[1] in self.clients}

    def start_scanning(self, interface):
        self.interface = interface
        if not self.put_interface_in_monitor_mode(interface):
            return False
        self.scanning = True
        threading.Thread(target=lambda: sniff(iface=self.monitor_interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.scanning), daemon=True).start()
        threading.Thread(target=self.channel_hopper, daemon=True).start()
        threading.Thread(target=self.cleanup_thread, daemon=True).start()
        return True

    def channel_hopper(self):
        channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
        while self.scanning:
            for channel in channels:
                if not self.scanning: break
                try:
                    subprocess.run(['sudo', 'iwconfig', self.monitor_interface, 'channel', str(channel)], capture_output=True, text=True)
                    time.sleep(0.5)
                except Exception: break

    def cleanup_thread(self):
        while self.scanning:
            self.cleanup_old_entries()
            time.sleep(10)

    def stop_scanning(self):
        self.scanning = False
        if self.monitor_interface:
            try:
                subprocess.run(['sudo', 'airmon-ng', 'stop', self.monitor_interface], capture_output=True, text=True)
            except: pass
        self.monitor_interface = None

    def get_network_data(self):
        clients_to_send = {mac: client for mac, client in self.clients.items() if not (self.filter_multicast and self.is_multicast(mac))}
        
        clients_list = []
        for mac, client_data in clients_to_send.items():
            client_copy = client_data.copy()
            if 'probed_ssids' in client_copy:
                client_copy['probed_ssids'] = list(client_copy['probed_ssids'])
            clients_list.append(client_copy)

        connections_to_send = {k: v for k, v in self.connections.items() if k[0] in self.access_points and k[1] in clients_to_send}
        connections_with_thickness = []
        
        now = datetime.now()
        # --- MODIFIED: Use a longer, more stable time window ---
        time_window = timedelta(seconds=15)

        for key, conn in connections_to_send.items():
            traffic_deque = self.connection_traffic[key]
            
            # Remove old packets from the window
            while traffic_deque and traffic_deque[0][0] < now - time_window:
                traffic_deque.popleft()

            # Calculate total bytes in the current window
            total_bytes = sum(size for timestamp, size in traffic_deque)
            
            new_conn = conn.copy()
            # Scale thickness based on total bytes in the window
            # MODIFIED: Changed denominator from 75000 to 25000
            new_conn['thickness'] = min(12, max(1, total_bytes / 10000))
            connections_with_thickness.append(new_conn)
        
        return {
            'access_points': list(self.access_points.values()),
            'clients': clients_list,
            'connections': connections_with_thickness
        }

scanner = WiFiScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces')
def get_interfaces():
    return jsonify({'interfaces': scanner.find_wifi_interfaces()})

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    interface = request.json.get('interface')
    if not interface or scanner.scanning:
        return jsonify({'error': 'Invalid request'}), 400
    if scanner.start_scanning(interface):
        return jsonify({'message': f'Started scanning on {interface}'})
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
    while True:
        if scanner.scanning:
            socketio.emit('network_update', scanner.get_network_data())
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