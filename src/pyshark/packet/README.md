# PyShark Packet Module

This module contains packet parsing, field access, and manipulation functionality for PyShark.

## Modules

### Core Packet Classes
- `packet.py` - Main packet class and parsing logic
- `packet_summary.py` - Packet summary and overview functionality
- `fields.py` - Packet field access and manipulation
- `common.py` - Common packet utilities and helpers
- `consts.py` - Packet parsing constants and definitions

### Layer Support
- `layers/` - Protocol layer definitions and parsing

## Key Features

### Packet Parsing
```python
import pyshark

# Parse packets from capture
cap = pyshark.FileCapture('example.pcap')
for packet in cap:
    print(f"Packet length: {packet.length}")
    print(f"Protocols: {packet.layers}")
```

### Field Access
```python
# Multiple ways to access packet fields
packet['ip'].dst          # Dictionary-style access
packet.ip.src            # Attribute-style access  
packet[2].src            # Layer index access

# Check if layer exists
if 'TCP' in packet:
    print(f"TCP destination port: {packet.tcp.dstport}")
```

### Field Information
```python
# Get field metadata
field = packet.ip.addr
print(f"Display name: {field.showname}")
print(f"Raw value: {field.raw_value}")
print(f"Binary value: {field.binary_value}")
print(f"Integer value: {field.int_value}")

# List all available fields
print(f"IP fields: {packet.ip.field_names}")
```

### Packet Summary
```python
# Get packet summary information
summary = packet.summary()
print(f"Summary: {summary}")

# Detailed packet information
info = packet.get_packet_info()
print(f"Timestamp: {info['timestamp']}")
print(f"Source: {info['src']}")
print(f"Destination: {info['dst']}")
```

## Packet Layer Structure

### Layer Hierarchy
```
Packet
├── Physical Layer (if present)
├── Data Link Layer (Ethernet, 802.11, etc.)
├── Network Layer (IP, IPv6, ARP, etc.)
├── Transport Layer (TCP, UDP, ICMP, etc.)
└── Application Layer (HTTP, DNS, FTP, etc.)
```

### Layer Access Examples
```python
# Access different layers
if 'ETH' in packet:
    eth_layer = packet.eth
    print(f"Source MAC: {eth_layer.src}")
    print(f"Destination MAC: {eth_layer.dst}")

if 'IP' in packet:
    ip_layer = packet.ip
    print(f"Source IP: {ip_layer.src}")
    print(f"Destination IP: {ip_layer.dst}")
    print(f"Protocol: {ip_layer.proto}")

if 'TCP' in packet:
    tcp_layer = packet.tcp
    print(f"Source Port: {tcp_layer.srcport}")
    print(f"Destination Port: {tcp_layer.dstport}")
    print(f"Flags: {tcp_layer.flags}")
```

## Field Types and Conversion

### Field Value Types
```python
# String representation
str_value = str(packet.ip.addr)

# Integer conversion (for numeric fields)
if hasattr(packet.ip.len, 'int_value'):
    length = packet.ip.len.int_value

# Binary data access
binary_data = packet.ip.addr.binary_value

# Hex representation
hex_value = packet.eth.src.replace(':', '')
```

### Custom Field Processing
```python
def extract_custom_fields(packet):
    """Extract custom fields from packet"""
    data = {}
    
    # Timestamp
    data['timestamp'] = float(packet.sniff_timestamp)
    
    # Layer information
    data['layers'] = packet.layers
    
    # Size information
    data['length'] = int(packet.length)
    
    # Protocol-specific data
    if 'IP' in packet:
        data['ip_src'] = str(packet.ip.src)
        data['ip_dst'] = str(packet.ip.dst)
        data['ip_proto'] = int(packet.ip.proto)
    
    if 'TCP' in packet:
        data['tcp_srcport'] = int(packet.tcp.srcport)
        data['tcp_dstport'] = int(packet.tcp.dstport)
        data['tcp_flags'] = str(packet.tcp.flags)
    
    return data
```

## Advanced Packet Analysis

### Protocol Detection
```python
def analyze_packet_protocols(packet):
    """Analyze protocols present in packet"""
    protocols = {
        'ethernet': 'ETH' in packet,
        'vlan': 'VLAN' in packet,
        'ip': 'IP' in packet,
        'ipv6': 'IPV6' in packet,
        'tcp': 'TCP' in packet,
        'udp': 'UDP' in packet,
        'http': 'HTTP' in packet,
        'https': 'TLS' in packet or 'SSL' in packet,
        'dns': 'DNS' in packet,
        'dhcp': 'DHCP' in packet
    }
    return protocols
```

### Packet Filtering
```python
def filter_packets_by_criteria(capture, criteria):
    """Filter packets based on custom criteria"""
    filtered_packets = []
    
    for packet in capture:
        if meets_criteria(packet, criteria):
            filtered_packets.append(packet)
    
    return filtered_packets

def meets_criteria(packet, criteria):
    """Check if packet meets filtering criteria"""
    # Size filtering
    if 'min_size' in criteria:
        if int(packet.length) < criteria['min_size']:
            return False
    
    # Protocol filtering
    if 'required_protocols' in criteria:
        for proto in criteria['required_protocols']:
            if proto not in packet:
                return False
    
    # Port filtering
    if 'ports' in criteria and 'TCP' in packet:
        if int(packet.tcp.dstport) not in criteria['ports']:
            return False
    
    return True
```

## Error Handling

### Common Issues and Solutions
```python
def safe_field_access(packet, layer, field):
    """Safely access packet fields with error handling"""
    try:
        if layer in packet:
            layer_obj = getattr(packet, layer.lower())
            if hasattr(layer_obj, field):
                return getattr(layer_obj, field)
        return None
    except AttributeError:
        return None
    except Exception as e:
        print(f"Error accessing {layer}.{field}: {e}")
        return None

# Usage example
src_ip = safe_field_access(packet, 'IP', 'src')
if src_ip:
    print(f"Source IP: {src_ip}")
```

### Field Validation
```python
def validate_packet_fields(packet):
    """Validate packet fields for completeness"""
    issues = []
    
    # Check required fields
    if 'ETH' in packet:
        if not hasattr(packet.eth, 'src') or not packet.eth.src:
            issues.append("Missing Ethernet source address")
    
    if 'IP' in packet:
        try:
            int(packet.ip.len)
        except (ValueError, AttributeError):
            issues.append("Invalid IP length field")
    
    return issues
```

## Integration with Enhanced Features

### Display Filter Integration
```python
from pyshark.display import WirelessFilters

# Use display filters with packet analysis
wireless = WirelessFilters()
beacon_filter = wireless.get_filter('beacon_frames')

cap = pyshark.FileCapture('wireless.pcap', 
                         display_filter=beacon_filter.filter_expression)

for packet in cap:
    # Packet will only contain beacon frames
    print(f"Beacon from BSSID: {packet.wlan.bssid}")
```

### Enhanced Capture Integration
```python
from pyshark.capture import EnhancedFileCapture

# Enhanced packet processing
cap = EnhancedFileCapture('network.pcap')
for packet in cap:
    # Additional packet metadata available
    if hasattr(packet, 'enhanced_info'):
        print(f"Enhanced data: {packet.enhanced_info}")
```

## Testing

Test packet functionality:

```bash
cd tests/packet
python -m pytest test_packet_operations.py -v
```

## See Also

- `../display/` - Display filters for packet filtering
- `../capture/` - Capture classes that create packet objects  
- `layers/` - Protocol layer definitions
- `../../tests/packet/` - Packet parsing tests