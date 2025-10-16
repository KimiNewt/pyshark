# PyShark Enhanced - Display Filters & WPA Decryption

Enhanced Python wrapper for tshark with comprehensive display filters and WPA/WPA2 decryption capabilities.

Extended documentation: http://kiminewt.github.io/pyshark

**Enhancement Features:**
- **146 Protocol-Specific Display Filters** (30 Ethernet + 61 Wireless + 55 Bluetooth)
- **WPA/WPA2 Decryption** with automatic credential detection  
- **Enhanced PyShark Integration** with encrypted capture support
- **Cross-Platform Compatibility** (Windows, Linux, macOS)
- **Production Ready** with comprehensive error handling

This enhanced version builds upon the original PyShark's tshark XML parsing capabilities while adding production-ready display filters and encrypted wireless analysis.

There are quite a few python packet parsing modules, this one is different because it doesn't actually parse any packets, it simply uses tshark's (wireshark command-line utility) ability to export XMLs to use its parsing.

This package allows parsing from a capture file or a live capture, using all wireshark dissectors you have installed.
Tested on Windows/Linux/macOS.

## Installation

### Version Support
Python 3.7+ is supported. An unsupported Python 2 version exists as [pyshark-legacy](https://github.com/KimiNewt/pyshark-legacy).

Supports all modern versions of tshark / wireshark but certain features may be unavailable on older versions.

### All Platforms
Simply run the following to install the latest from pypi:
```bash
pip install pyshark
```

Or install from the git repository:
```bash
git clone https://github.com/KimiNewt/pyshark.git
cd pyshark/src
python setup.py install
```

### Enhanced Version Installation
For the enhanced version with 146+ display filters and WPA decryption:
```bash
git clone https://github.com/D14b0l1c/pyshark.git
cd pyshark
pip install -r requirements.txt
python working_demo.py  # Test installation
```

### Mac OS X
You may have to install libxml which can be unexpected. If you receive an error from clang or an error message about libxml, run the following:
```bash
xcode-select --install
pip install libxml
```
You will probably have to accept a EULA for XCode so be ready to click an "Accept" dialog in the GUI.

## Enhanced Features

### Display Filters (146 Total)
```python
from src.pyshark.display.wireless_filters import WirelessFilters

# Get all wireless filters
wireless = WirelessFilters()
filters = wireless.get_all_filters()

# Use specific filter  
beacon_filter = filters['beacon_frames']
print(beacon_filter.filter_expression)  # wlan.fc.type_subtype == 0x08
```

### WPA/WPA2 Decryption
```python
from src.pyshark.display.encrypted_capture import analyze_encrypted_pcap

# Analyze encrypted PCAP with auto-decryption
results = analyze_encrypted_pcap("encrypted.pcap")
print(f"Decrypted {results['packets_total']} packets")
```

### Test Data Sources
- **Generated Test Data**: `tests/data/` contains protocol-specific PCAP files
- **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures  
  Comprehensive collection including WPA encrypted traffic, VoIP, IoT protocols, and more

### Enhanced Demo
Run `python working_demo.py` to see all 146 display filters in action.
Run `python comparison_demo.py` to see WPA decryption comparison demo.

## Basic Usage

### Reading from a capture file:

```python
>>> import pyshark
>>> cap = pyshark.FileCapture('/tmp/mycapture.cap')
>>> cap
<FileCapture /tmp/mycapture.cap (589 packets)>
>>> print(cap[0])
Packet (Length: 698)
Layer ETH:
        Destination: aa:bb:cc:dd:ee:ff
        Source: 00:11:22:33:44:55
        Type: IP (0x0800)
Layer IP:
        Version: 4
        IHL: 5
        DSCP: 0
        ECN: 0
        Length: 684
        Identification: 0x254f
        Flags: 0x40
        Fragment offset: 0
        TTL: 1
        Protocol: TCP (6)
        Header checksum: 0x6649
        Source: 192.168.0.1
        Destination: 192.168.0.2
Layer TCP:
        Source port: 80
        Destination port: 12345
        [Stream index: 0]
        [TCP Segment Len: 644]
        Sequence number: 0
        [Next sequence number: 644]
        Acknowledgment number: 1
        Header length: 20
        Flags: 0x18 (PSH, ACK)
        Window size value: 1024
        [Calculated window size: 1024]
        Checksum: 0x1234
        Options: (0 bytes)
Layer DATA:
        Data (644 bytes)
>>> cap.close()
```

### Reading from a live interface:

```python
>>> capture = pyshark.LiveCapture(interface='eth0')
>>> capture.sniff(timeout=50)
>>> capture
<LiveCapture (5 packets)>
>>> capture[3]
<UDP/HTTP Packet>
```

### Reading from a remote interface:

```python
>>> capture = pyshark.RemoteCapture('192.168.1.101', 'eth0')
>>> capture.sniff(timeout=50)
>>> capture
<RemoteCapture>
```

#### Other options

* **param remote_host**: The remote host to capture on (IP or hostname).
Should be running rpcapd.
* **param remote_interface**: The remote interface on the remote machine to
capture on. Note that on windows it is not the device display name but the
true interface name (i.e. \\Device\\NPF_..).
* **param remote_port**: The remote port the rpcapd service is listening on
* **param bpf_filter**: BPF (tcpdump) filter to apply on the cap before reading.
* **param only_summaries**: Only produce packet summaries, much faster but
includes very little information
* **param disable_protocol**: Disable detection of a protocol (tshark > version 2)
* **param decryption_key**: Key used to encrypt and decrypt captured traffic.
* **param encryption_type**: Standard of encryption used in captured traffic
(must be either 'wep', 'wpa-pwd', or 'wpa-psk'. Defaults to wpa-psk).
* **param tshark_path**: Path of the tshark binary

### Accessing packet data:

Data can be accessed in multiple ways.
Packets are divided into layers, first you have to reach the appropriate layer and then you can select your field.

All of the following work:

```python
>>> packet['ip'].dst
192.168.0.1
>>> packet.ip.src
192.168.0.100
>>> packet[2].src
192.168.0.100
```

To test whether a layer is in a packet, you can use its name:

```python
>>> 'IP' in packet
True
```

To see all possible field names, use the `packet.layer.field_names` attribute (i.e. `packet.ip.field_names`) or the autocomplete function on your interpreter.

You can also get the original binary data of a field, or a pretty description of it:

```python
>>> p.ip.addr.showname
'Source or Destination Address: 10.0.0.10 (10.0.0.10)'
# Find some new attributes as well:
>>> p.ip.addr.int_value
167772170
>>> p.ip.addr.binary_value
b'\\n\\x00\\x00\\n'
```

### Decrypting packet captures

Pyshark supports automatic decryption of traces using the WEP, WPA-PWD, and WPA-PSK standards (WPA-PWD is the default).

```python
>>> cap1 = pyshark.FileCapture('/tmp/capture1.cap', decryption_key='password')
>>> cap2 = pyshark.LiveCapture(interface='wif0', decryption_key='password', encryption_type='wpa-psk')
```

A tuple of supported encryption standards, SUPPORTED_ENCRYPTION_STANDARDS,
exists in each capture class.

```python
>>> pyshark.FileCapture.SUPPORTED_ENCRYPTION_STANDARDS
('wep', 'wpa-pwd', 'wpa-psk')
>>> pyshark.LiveCapture.SUPPORTED_ENCRYPTION_STANDARDS  
('wep', 'wpa-pwd', 'wpa-psk')
```

### Reading from a file using a display filter

Pyshark display filters can be helpful in analyzing application focused traffic.
BPF filters do not offer as much flexibility as Wireshark's display filters.

```python
>>> cap1 = pyshark.FileCapture('/tmp/capture1.cap', display_filter="dns")
>>> cap2 = pyshark.LiveCapture(interface='en0', display_filter="tcp.analysis.retransmission")
```

## Enhanced Display Filters & Protocol Analysis

PyShark now includes comprehensive **protocol-specific display filters** and **standalone filtering capabilities** that work without requiring Wireshark/tshark installation.

### Protocol-Specific Filters

Built-in filters organized by protocol with 146+ predefined filters:

```python
>>> from pyshark.display import EthernetFilters, WirelessFilters, BluetoothFilters

# Ethernet Protocol Filters (30+ filters)
>>> ethernet_filter = EthernetFilters.BROADCAST_FRAMES  # "eth.dst == ff:ff:ff:ff:ff:ff"
>>> vlan_filter = EthernetFilters.VLAN_TAGGED          # "vlan"
>>> jumbo_filter = EthernetFilters.JUMBO_FRAMES        # "frame.len > 1518"

# 802.11 Wireless Filters (61+ filters)  
>>> beacon_filter = WirelessFilters.BEACON_FRAMES      # "wlan.fc.type_subtype == 0x08"
>>> probe_filter = WirelessFilters.PROBE_REQUESTS      # "wlan.fc.type_subtype == 0x04"
>>> handshake_filter = WirelessFilters.WPA_HANDSHAKE   # "eapol"

# Bluetooth Filters (55+ filters)
>>> inquiry_filter = BluetoothFilters.INQUIRY_SCAN     # "hci_h4.type == 0x01 && hci_cmd.opcode == 0x0401"
>>> audio_filter = BluetoothFilters.A2DP_AUDIO         # "bta2dp"
```

### Enhanced File Capture

Advanced capture capabilities with enhanced filtering and analysis:

```python
>>> from pyshark.capture import EnhancedFileCapture

# Create enhanced capture with security analysis
>>> cap = EnhancedFileCapture('network.pcap')
>>> security_cap = cap.create_security_analyzer(
...     detect_suspicious_traffic=True,
...     analyze_failed_connections=True,
...     export_objects={'http': '/tmp/extracted/'}
... )

# Web traffic analysis view
>>> web_cap = cap.create_web_analysis_view(
...     include_headers=True,
...     track_sessions=True,
...     decode_content=True
... )

# Performance analysis with custom timing fields
>>> perf_cap = cap.create_performance_analyzer(
...     timing_fields=['tcp.time_delta', 'http.time'],
...     slow_threshold=0.1
... )
```

### Standalone Display Filters

Pure Python filtering that works without Wireshark installation:

```python
>>> from pyshark.display import StandaloneDisplayFilter

>>> filter = StandaloneDisplayFilter()
>>> filter.add_protocol_condition('tcp')
>>> filter.add_field_condition('tcp.dstport', '==', '443')
>>> filter.add_logical_operator('or')
>>> filter.add_protocol_condition('udp')
>>> print(filter.build_filter())
tcp and tcp.dstport == 443 or udp

# Advanced filtering with protocol-specific builders
>>> from pyshark.display import EthernetFilterBuilder
>>> eth_builder = EthernetFilterBuilder()
>>> complex_filter = (eth_builder
...     .vlan_id(100)
...     .source_mac('aa:bb:cc:dd:ee:ff')
...     .frame_size_range(64, 1518)
...     .build())
```

### Protocol Version Detection

Automatic detection and analysis of protocol capabilities:

```python
>>> from pyshark.display import ProtocolVersions

# Detect Ethernet capabilities
>>> eth_info = ProtocolVersions.ethernet_capabilities()
>>> print(f"Supports VLANs: {eth_info['vlan_support']}")
>>> print(f"Max frame size: {eth_info['max_frame_size']}")

# Wireless standard detection
>>> wifi_info = ProtocolVersions.wireless_capabilities()
>>> print(f"Standards: {wifi_info['supported_standards']}")  # 802.11a/b/g/n/ac/ax
>>> print(f"Security: {wifi_info['security_protocols']}")    # WEP/WPA/WPA2/WPA3
```

## Directory Structure

```
pyshark/
├── src/pyshark/          # Core PyShark modules
│   ├── capture/          # Enhanced capture capabilities
│   ├── display/          # Display filters and analysis
│   ├── packet/           # Packet parsing and manipulation
│   └── tshark/           # TShark interface
├── tests/                # Comprehensive test suite
│   ├── data/             # Test PCAP files and generators
│   ├── capture/          # Capture functionality tests
│   ├── display/          # Display filter tests
│   └── packet/           # Packet parsing tests
├── examples/             # Usage examples and demos
├── comparison_demo.py    # WPA decryption comparison
├── working_demo.py       # 146 filter demonstration
└── README.md            # This file
```

## Examples Directory

The `examples/` directory contains comprehensive usage demonstrations:

- `enhanced_display_filter_examples.py` - Complete usage demonstrations including:
  - Security analysis workflows
  - Performance monitoring
  - Custom field extraction
  - Protocol layer filtering
  - Network troubleshooting

- `enhanced_file_capture_examples.py` - Advanced capture techniques:
  - Multi-protocol analysis
  - Custom field extraction
  - Performance monitoring
  - Security analysis

## Testing

All enhancements include comprehensive test coverage:

```bash
# Run enhanced functionality tests
python -m pytest tests/test_standalone_functionality.py -v

# Results: 22/22 tests passed
# - Standalone imports and filtering
# - Protocol-specific display filters
# - Enhanced capture capabilities
# - WPA decryption functionality

# Run all tests
python -m pytest tests/ -v

# Generate test data
cd tests/data
python generate_ethernet_test.py
python generate_wireless_test.py  
python generate_bluetooth_test.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE.txt for details.

## Enhanced Features Summary

- **146 Protocol-Specific Display Filters**: Ethernet (30), Wireless (61), Bluetooth (55)
- **WPA/WPA2 Decryption**: Full integration with automatic credential detection
- **Enhanced Capture Classes**: Advanced filtering and analysis capabilities
- **Standalone Filtering**: Pure Python filtering without Wireshark dependency
- **Test Data Generation**: Comprehensive PCAP file generators for all protocols
- **Cross-Platform Support**: Windows, Linux, macOS compatibility
- **Production Ready**: Error handling, logging, and performance optimization

For detailed usage examples, see the `examples/` directory and run `python working_demo.py`.