# PyShark Display Filter Test Data
=============================================

This directory contains scripts to generate test PCAP files for validating PyShark display filter functionality.

## Generated Test Files

### 1. Ethernet Test Data (`ethernet_test.pcap`)
- **Generator**: `generate_ethernet_test.py`
- **Protocols**: IPv4, IPv6, ARP, VLAN (802.1Q), DHCP
- **Frame Types**: TCP, UDP, ICMP, multicast, broadcast
- **Test Coverage**: 
  - Multiple MAC addresses
  - VLAN tagged frames (VLANs 100, 200)
  - ARP request/reply sequences
  - DHCP discovery
  - DNS query/response pairs
  - Large frames (jumbo)
  - Multicast traffic

### 2. Wireless Test Data (`wireless_test.pcap`)
- **Generator**: `generate_wireless_test.py`
- **Standard**: 802.11 (WiFi)
- **Frame Types**: Management, Control, Data
- **Test Coverage**:
  - Beacon frames with SSID broadcasts
  - Probe request/response sequences
  - Authentication and association flows
  - QoS data frames
  - Control frames (RTS, CTS, ACK)
  - Deauthentication and action frames
  - Multiple BSSIDs and channels
  - RadioTap headers

### 3. Bluetooth Test Data (`bluetooth_test.pcap`)
- **Generator**: `generate_bluetooth_test.py`
- **Protocols**: Classic Bluetooth (BR/EDR) and Bluetooth Low Energy (BLE)
- **Test Coverage**:
  - HCI commands and events
  - L2CAP connection management
  - RFCOMM protocol frames
  - BLE advertisements and connections
  - GATT protocol operations
  - Multiple device addresses
  - Connection establishment/teardown

## Quick Start

### Generate All Test Files
```bash
cd tests/data
python generate_all_test_pcaps.py
```

### Generate Individual Files
```bash
# Ethernet only
python generate_ethernet_test.py

# Wireless only  
python generate_wireless_test.py

# Bluetooth only
python generate_bluetooth_test.py
```

## Requirements

```bash
pip install scapy
```

**Note**: Bluetooth frame generation may have limitations depending on your Scapy version and system Bluetooth capabilities.

## Using Test Data with PyShark Display Filters

```python
import pyshark
from pyshark.display.ethernet_filters import EthernetFilters
from pyshark.display.wireless_filters import WirelessFilters
from pyshark.display.bluetooth_filters import BluetoothFilters

# Load test data
eth_cap = pyshark.FileCapture('tests/data/ethernet_test.pcap', display_filter='eth')
wifi_cap = pyshark.FileCapture('tests/data/wireless_test.pcap', display_filter='wlan')
bt_cap = pyshark.FileCapture('tests/data/bluetooth_test.pcap', display_filter='bluetooth')

# Test ethernet filters
ethernet_filter = EthernetFilters.get_all_filters()['ipv4_only']
ipv4_cap = pyshark.FileCapture('tests/data/ethernet_test.pcap', 
                               display_filter=ethernet_filter.filter_expression)

# Test wireless filters  
beacon_filter = WirelessFilters.get_all_filters()['beacon_frames']
beacon_cap = pyshark.FileCapture('tests/data/wireless_test.pcap',
                                 display_filter=beacon_filter.filter_expression)

# Test bluetooth filters
hci_filter = BluetoothFilters.get_all_filters()['hci_commands']
hci_cap = pyshark.FileCapture('tests/data/bluetooth_test.pcap',
                              display_filter=hci_filter.filter_expression)
```

## File Structure

```
tests/data/
├── README.md                     # This file
├── generate_all_test_pcaps.py   # Generate all test files
├── generate_ethernet_test.py    # Ethernet test generator
├── generate_wireless_test.py    # Wireless test generator
├── generate_bluetooth_test.py   # Bluetooth test generator
├── ethernet_test.pcap           # Generated Ethernet test data
├── wireless_test.pcap           # Generated Wireless test data
└── bluetooth_test.pcap          # Generated Bluetooth test data
```

## Validation

Each generator script includes validation checks to ensure the generated PCAP files contain the expected packet types and can be read by PyShark. The scripts output detailed information about what was included in each test file.

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure Scapy is installed with Bluetooth support:
   ```bash
   pip install scapy[complete]
   ```

2. **Bluetooth Limitations**: Some Bluetooth frame types may not be available depending on your Scapy version. The script will fall back to synthetic frames for testing.

3. **Permissions**: On some systems, Bluetooth operations may require elevated privileges.

### Testing Generated Files

```python
# Quick validation
import pyshark

# Test file loading
cap = pyshark.FileCapture('tests/data/ethernet_test.pcap')
print(f"Loaded {len(list(cap))} ethernet packets")

cap = pyshark.FileCapture('tests/data/wireless_test.pcap') 
print(f"Loaded {len(list(cap))} wireless packets")

cap = pyshark.FileCapture('tests/data/bluetooth_test.pcap')
print(f"Loaded {len(list(cap))} bluetooth packets")
```

---

**Generated for PyShark Display Filter Enhancement Project**  
Author: D14b0l1c  
Target: Enhanced display filtering for packet analysis