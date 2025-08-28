# WiFi Network Scanner

A real-time WiFi network scanner with interactive web interface that maps relationships between access points and clients. Built for Kali Linux ARM64.

## Features

- **Real-time WiFi scanning** in monitor mode
- **Interactive network visualization** with D3.js
- **AP-Client relationship mapping** with dynamic connections
- **Packet transmission visualization** via line thickness
- **Directional traffic indicators** with arrows
- **Auto-cleanup** of inactive devices (1 minute timeout)
- **Zoom and pan** interface for exploring large networks
- **Real-time statistics** and device information
- **Modern web interface** with responsive design

## Requirements

### System Requirements
- Kali Linux ARM64 (optimized for ARM64 architecture)
- WiFi card with monitor mode support
- Python 3.7+
- Root privileges (for monitor mode)
- Internet connection for package installation

### Hardware Requirements
- WiFi adapter that supports monitor mode
- Sufficient RAM for packet processing
- Network connectivity for web interface

## Installation

1. **Clone or copy the project files** to your Kali Linux ARM64 machine

2. **Run the setup script** to install dependencies:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   
   **If you encounter virtual environment permission issues** (common on mounted filesystems):
   ```bash
   chmod +x setup_alt.sh
   ./setup_alt.sh
   ```
   
   The setup script will:
   - Verify ARM64 architecture compatibility
   - Install Kali Linux WiFi tools metapackage (`kali-tools-802-11`)
   - Create and configure Python virtual environment
   - Install all required Python packages
   - Set up proper permissions for WiFi monitoring
   - Validate all installations automatically

3. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate
   ```

4. **Validate the installation** (optional):
   ```bash
   ./validate.sh
   ```

## Usage

### Starting the Scanner

1. **Activate the virtual environment** (if not already active):
   ```bash
   source venv/bin/activate
   ```

2. **Run the WiFi scanner**:
   ```bash
   python3 wifi_scanner.py
   ```

3. **Open your web browser** and navigate to:
   ```
   http://localhost:5000
   ```

### Using the Web Interface

1. **Select WiFi Interface**: Choose your WiFi interface from the dropdown
2. **Start Scan**: Click "Start Scan" to begin monitoring
3. **View Network**: The interface will show:
   - **Red circles**: Access Points (larger circles)
   - **Blue circles**: Clients (smaller circles)
   - **White lines**: Connections between APs and clients
   - **Line thickness**: Indicates packet traffic volume
   - **Arrows**: Show bidirectional communication

### Interface Controls

- **Zoom**: Mouse wheel or pinch gestures
- **Pan**: Click and drag to move around
- **Node Details**: Hover over nodes for detailed information
- **Drag Nodes**: Click and drag nodes to reposition them
- **Statistics**: View real-time counts in the top-right panel

## Technical Details

### Dependencies Optimized for Kali ARM64

The application uses the following optimized dependencies:

**System Packages (via Kali metapackage):**
- `kali-tools-802-11` - Metapackage containing aircrack-ng, kismet, and other WiFi tools
- `aircrack-ng` - Provides `airmon-ng` for monitor mode
- `iw` - Modern replacement for `iwconfig`
- `tcpdump` - Packet capture capabilities

**Python Packages:**
- `flask` - Web framework for the interface
- `flask-socketio` - Real-time WebSocket communication
- `scapy` - Packet manipulation and capture
- `netifaces` - Network interface detection
- `psutil` - System and process utilities
- `eventlet` - Asynchronous networking library

### Packet Types Monitored

- **Beacon frames**: Access point discovery
- **Probe requests/responses**: Client scanning
- **Association requests/responses**: Client connections
- **Authentication frames**: Security handshakes

### Data Processing

- **Real-time packet capture** using Scapy
- **Automatic device classification** (AP vs Client)
- **Connection tracking** between devices
- **Packet counting** for traffic analysis
- **Timeout management** (1-minute cleanup)

### Web Interface Features

- **WebSocket communication** for real-time updates
- **D3.js force-directed graph** for network visualization
- **Responsive design** for various screen sizes
- **Interactive tooltips** with device details
- **Live statistics** updating every 2 seconds

## Troubleshooting

### Common Issues

1. **"No WiFi interfaces found"**
   - Ensure your WiFi card is properly detected
   - Check if the card supports monitor mode
   - Run `iwconfig` or `iw dev` to list interfaces

2. **"Permission denied" for monitor mode**
   - Ensure you're running as root or have proper permissions
   - Check if the user is in the `netdev` group
   - Log out and back in after setup script

3. **"Failed to put interface in monitor mode"**
   - Check if the interface is already in use
   - Stop any existing monitor interfaces: `sudo airmon-ng stop <interface>`
   - Ensure no other WiFi tools are using the interface

4. **No packets being captured**
   - Verify the interface is in monitor mode: `iwconfig <interface>`
   - Check if there are active WiFi networks nearby
   - Ensure the interface supports the frequency bands in use

5. **Environment validation issues**
   - Run the validation script: `./validate.sh`
   - Check for missing dependencies or permissions
   - Ensure virtual environment is activated

6. **Virtual environment permission errors**
   - Run the fix script: `./fix_venv.sh`
   - Use alternative setup: `./setup_alt.sh`
   - Move project to local directory: `cp -r . /home/$USER/wifi-scanner/`

7. **Packet capture permission errors (Errno 1)**
   - Run with sudo: `./run_with_sudo.sh`
   - Or set capabilities: `sudo ./setup_capabilities.sh`
   - Ensure user is in netdev group and logged out/in

### Manual Interface Setup

If the automatic monitor mode setup fails:

```bash
# List available interfaces
iw dev

# Put interface in monitor mode manually
sudo airmon-ng start wlan0

# Check monitor interface name
iwconfig

# Verify monitor mode
iwconfig wlan0mon
```

### Debug Mode

To run with debug output:

```bash
python3 wifi_scanner.py --debug
```

## Security Considerations

- **Network monitoring** should only be performed on networks you own or have permission to monitor
- **Monitor mode** requires root privileges
- **Packet capture** may be subject to local laws and regulations
- **Use responsibly** and in accordance with applicable laws

## Performance Optimization

### For Large Networks

- **Increase cleanup frequency** for faster device removal
- **Adjust packet processing** for higher throughput
- **Optimize visualization** for many concurrent connections

### Memory Management

- **Monitor memory usage** during long scanning sessions
- **Restart periodically** for very long monitoring sessions
- **Adjust timeout values** based on network activity

## Development

### Project Structure

```
Scanner/
├── wifi_scanner.py      # Main application
├── requirements.txt     # Python dependencies
├── setup.sh            # Installation script
├── setup_alt.sh        # Alternative setup (for permission issues)
├── setup_capabilities.sh # Packet capture capabilities setup
├── fix_venv.sh         # Virtual environment fix script
├── run.sh              # Launcher script
├── run_with_sudo.sh    # Run with sudo privileges
├── validate.sh         # Environment validation script
├── check_interface_mode.sh # Interface mode checker
├── kill_interference.sh # Kill interfering processes
├── test_interfaces.py  # Interface testing script
├── wifi-scanner.service # Systemd service file
├── templates/
│   └── index.html      # Web interface
└── README.md           # This file
```

### Adding Features

- **New packet types**: Extend the `packet_handler` method
- **Additional statistics**: Modify the `get_network_data` method
- **UI enhancements**: Update the HTML template and JavaScript
- **Export functionality**: Add data export endpoints

## License

This project is for educational and authorized network monitoring purposes only. Users are responsible for complying with all applicable laws and regulations.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the console output for error messages
3. Ensure all dependencies are properly installed
4. Verify your WiFi card supports monitor mode

## Changelog

### Version 1.0
- Initial release
- Real-time WiFi scanning
- Interactive web interface
- AP-Client relationship mapping
- Packet traffic visualization
