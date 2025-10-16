# PyShark Display Filters Module

This module contains enhanced display filters and analysis capabilities for PyShark, providing 146+ protocol-specific filters and standalone filtering functionality.

## Modules

### Core Filter Modules
- `ethernet_filters.py` - 30+ Ethernet protocol filters
- `wireless_filters.py` - 61+ 802.11 wireless filters  
- `bluetooth_filters.py` - 55+ Bluetooth protocol filters
- `protocol_filters.py` - Core protocol filter definitions
- `enhanced_display_filters.py` - Main filter interface

### Analysis Modules
- `encrypted_analysis.py` - Encrypted traffic analysis
- `encrypted_capture.py` - WPA/WPA2 decryption capabilities
- `standalone_filters.py` - Pure Python filtering without Wireshark
- `protocol_versions.py` - Protocol version detection

## Filter Categories

### Ethernet Filters (30 total)
```python
from pyshark.display.ethernet_filters import EthernetFilters

# Access specific filters
broadcast_filter = EthernetFilters.BROADCAST_FRAMES
vlan_filter = EthernetFilters.VLAN_TAGGED
jumbo_filter = EthernetFilters.JUMBO_FRAMES
```

### Wireless Filters (61 total)
```python
from pyshark.display.wireless_filters import WirelessFilters

# Management frames
beacon_filter = WirelessFilters.BEACON_FRAMES
probe_filter = WirelessFilters.PROBE_REQUESTS

# Security
wpa_filter = WirelessFilters.WPA_HANDSHAKE
wep_filter = WirelessFilters.WEP_ENCRYPTED
```

### Bluetooth Filters (55 total)
```python
from pyshark.display.bluetooth_filters import BluetoothFilters

# HCI layer
inquiry_filter = BluetoothFilters.INQUIRY_SCAN
connect_filter = BluetoothFilters.CONNECTION_COMPLETE

# Protocol specific
a2dp_filter = BluetoothFilters.A2DP_AUDIO
hid_filter = BluetoothFilters.HID_DATA
```

## Enhanced Analysis

### WPA Decryption
```python
from pyshark.display.encrypted_capture import analyze_encrypted_pcap

# Automatic WPA decryption
results = analyze_encrypted_pcap(
    "encrypted.pcap",
    ssid="MyNetwork", 
    password="MyPassword"
)
```

### Standalone Filtering
```python
from pyshark.display.standalone_filters import StandaloneDisplayFilter

# Pure Python filtering
filter = StandaloneDisplayFilter()
filter.add_protocol_condition('tcp')
filter.add_field_condition('tcp.dstport', '==', '443')
expression = filter.build_filter()
```

## Usage Examples

### Basic Filter Usage
```python
from pyshark.display import EthernetFilters, WirelessFilters

# Get all available filters
ethernet_filters = EthernetFilters.get_all_filters()
wireless_filters = WirelessFilters.get_all_filters()

# Use with PyShark capture
import pyshark
cap = pyshark.FileCapture('test.pcap', 
                         display_filter=ethernet_filters['broadcast_frames'])
```

### Advanced Protocol Analysis
```python
from pyshark.display.protocol_versions import ProtocolVersions

# Detect protocol capabilities
eth_caps = ProtocolVersions.ethernet_capabilities()
wifi_caps = ProtocolVersions.wireless_capabilities()

print(f"VLAN support: {eth_caps['vlan_support']}")
print(f"WiFi standards: {wifi_caps['supported_standards']}")
```

## Filter Expression Reference

All filters generate standard Wireshark display filter expressions:

- **Ethernet**: `eth.dst`, `eth.src`, `vlan.id`, `frame.len`
- **Wireless**: `wlan.fc.type_subtype`, `wlan.bssid`, `eapol`
- **Bluetooth**: `hci_h4.type`, `bta2dp`, `btl2cap`

## Testing

Test the display filters:

```bash
cd tests/display
python -m pytest test_display_module.py -v
```

## Integration

These filters integrate seamlessly with:
- Standard PyShark FileCapture and LiveCapture
- Enhanced capture classes in `../capture/`
- Standalone analysis without Wireshark installation