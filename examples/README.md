# PyShark Examples

This directory contains comprehensive examples demonstrating the enhanced PyShark functionality including display filters, WPA decryption, and advanced analysis capabilities.

## Example Files

### Enhanced Display Filter Examples (`enhanced_display_filter_examples.py`)
Comprehensive demonstrations of the 146+ protocol-specific display filters:

**Features Demonstrated:**
- Ethernet Protocol Filters (30 filters)
- Wireless 802.11 Filters (61 filters)  
- Bluetooth Protocol Filters (55 filters)
- Security analysis workflows
- Performance monitoring
- Custom field extraction
- Protocol layer filtering
- Network troubleshooting

**Usage:**
```bash
python enhanced_display_filter_examples.py
```

### Enhanced File Capture Examples (`enhanced_file_capture_examples.py`)
Advanced capture techniques and analysis methods:

**Features Demonstrated:**
- Multi-protocol analysis
- Custom field extraction
- Performance monitoring
- Security analysis
- Object extraction
- Session tracking
- Cross-protocol correlation

**Usage:**
```bash
python enhanced_file_capture_examples.py
```

## Quick Start Examples

### Basic Display Filter Usage
```python
from pyshark.display import WirelessFilters, EthernetFilters, BluetoothFilters

# Get wireless beacon frames
wireless = WirelessFilters()
beacon_filter = wireless.get_filter('beacon_frames')
print(f"Filter: {beacon_filter.filter_expression}")

# Get Ethernet broadcast frames  
ethernet = EthernetFilters()
broadcast_filter = ethernet.get_filter('broadcast_frames')
print(f"Filter: {broadcast_filter.filter_expression}")

# Get Bluetooth inquiry scans
bluetooth = BluetoothFilters()
inquiry_filter = bluetooth.get_filter('inquiry_scan')
print(f"Filter: {inquiry_filter.filter_expression}")
```

### Enhanced Capture Analysis
```python
from pyshark.capture import EnhancedFileCapture

# Create enhanced capture
cap = EnhancedFileCapture('network.pcap')

# Security analysis
security_analyzer = cap.create_security_analyzer(
    detect_suspicious_traffic=True,
    analyze_failed_connections=True
)

# Performance analysis
perf_analyzer = cap.create_performance_analyzer(
    timing_fields=['tcp.time_delta'],
    slow_threshold=0.1
)

# Web traffic analysis
web_analyzer = cap.create_web_analysis_view(
    include_headers=True,
    track_sessions=True
)
```

### WPA Decryption Example
```python
from pyshark.display.encrypted_capture import analyze_encrypted_pcap

# Analyze encrypted wireless capture
results = analyze_encrypted_pcap(
    pcap_file="encrypted_wireless.pcap",
    ssid="MyNetwork",
    password="MyPassword"
)

print(f"Decrypted {results['packets_total']} packets")
print(f"Found {len(results['protocols'])} protocols")
```

## Example Datasets

Use the test data generators to create example datasets:

```bash
# Generate test data
cd ../tests/data/
python generate_ethernet_test.py    # Ethernet examples
python generate_wireless_test.py    # Wireless examples  
python generate_bluetooth_test.py   # Bluetooth examples
```

## Running Examples

### Prerequisites
```bash
# Install dependencies
pip install -r ../requirements.txt

# Ensure PyShark is installed
cd ../src
pip install -e .
```

### Execute Examples
```bash
# Run display filter examples
python enhanced_display_filter_examples.py

# Run capture examples  
python enhanced_file_capture_examples.py

# Run working demo (all 146 filters)
cd ..
python working_demo.py

# Run WPA comparison demo
python comparison_demo.py
```

## Example Output

### Display Filter Demo Output
```
PyShark Enhanced Display Filters Examples
==========================================

1. ETHERNET FILTERS (30 total)
   ✓ broadcast_frames: eth.dst == ff:ff:ff:ff:ff:ff
   ✓ vlan_tagged: vlan
   ✓ jumbo_frames: frame.len > 1518

2. WIRELESS FILTERS (61 total)  
   ✓ beacon_frames: wlan.fc.type_subtype == 0x08
   ✓ probe_requests: wlan.fc.type_subtype == 0x04
   ✓ wpa_handshake: eapol

3. BLUETOOTH FILTERS (55 total)
   ✓ inquiry_scan: hci_h4.type == 0x01 && hci_cmd.opcode == 0x0401
   ✓ a2dp_audio: bta2dp
   ✓ hid_data: bthid
```

### Capture Analysis Output
```
Enhanced File Capture Analysis
==============================

Security Analysis:
- Suspicious connections: 3
- Failed connections: 12
- Certificate issues: 1

Performance Metrics:
- Average RTT: 45.2ms
- Throughput: 125.3 Mbps
- Packet loss: 0.02%

Protocol Distribution:
- TCP: 65%
- UDP: 25%  
- ICMP: 10%
```

## Integration Examples

### Custom Analysis Pipeline
```python
def analyze_network_capture(pcap_file):
    """Complete network analysis pipeline example"""
    
    # Enhanced capture with all analyzers
    cap = EnhancedFileCapture(pcap_file)
    
    # Security analysis
    security = cap.create_security_analyzer(
        detect_suspicious_traffic=True,
        analyze_failed_connections=True,
        export_objects={'http': '/tmp/extracted/'}
    )
    
    # Performance analysis
    performance = cap.create_performance_analyzer(
        timing_fields=['tcp.time_delta', 'tcp.analysis.ack_rtt'],
        calculate_throughput=True
    )
    
    # Web analysis
    web = cap.create_web_analysis_view(
        include_headers=True,
        track_sessions=True,
        decode_content=True
    )
    
    # Generate comprehensive report
    return {
        'security_findings': security.get_security_findings(),
        'performance_metrics': performance.get_performance_metrics(),
        'web_sessions': web.get_session_summary(),
        'protocol_summary': cap.get_protocol_summary()
    }
```

## Contributing Examples

To contribute new examples:

1. Create a new Python file with descriptive name
2. Include comprehensive docstrings
3. Add usage examples with sample output
4. Test with the provided test data
5. Update this README with the new example

## See Also

- `../working_demo.py` - Complete 146 filter demonstration
- `../comparison_demo.py` - WPA decryption comparison
- `../tests/data/` - Test data generators
- `../src/pyshark/display/` - Display filter modules
- `../src/pyshark/capture/` - Enhanced capture modules