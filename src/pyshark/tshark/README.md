# PyShark TShark Interface Module

This module provides the interface between PyShark and the TShark command-line tool, handling TShark execution, XML parsing, and output processing.

## Modules

### Core TShark Interface
- `tshark.py` - Main TShark interface and execution logic
- `output_parser/` - TShark XML output parsing utilities

## Key Features

### TShark Execution
```python
from pyshark.tshark import tshark

# Execute TShark with specific parameters
result = tshark.get_process_result([
    '-r', 'input.pcap',        # Read from file
    '-T', 'pdml',              # Export as XML
    '-Y', 'tcp.port == 80'     # Display filter
])
```

### XML Output Parsing
```python
# Parse TShark XML output into Python objects
from pyshark.tshark.output_parser import TSharkXMLParser

parser = TSharkXMLParser()
packets = parser.parse_xml_output(xml_data)

for packet in packets:
    print(f"Packet: {packet.number}")
    for layer in packet.layers:
        print(f"  Layer: {layer.name}")
```

### Process Management
```python
# Long-running TShark process for live capture
process = tshark.get_tshark_process([
    '-i', 'eth0',              # Capture interface
    '-T', 'pdml',              # XML output
    '-l'                       # Line buffering
])

# Read packets in real-time
for packet_xml in tshark.read_packet_xml(process):
    packet = parser.parse_packet_xml(packet_xml)
    # Process packet...
```

## TShark Command Line Interface

### Common TShark Parameters
```python
# File input/output
['-r', 'input.pcap']           # Read from file
['-w', 'output.pcap']          # Write to file
['-F', 'pcap']                 # Output format

# Interface capture
['-i', 'eth0']                 # Capture interface
['-f', 'tcp port 80']          # BPF filter
['-c', '100']                  # Packet count limit

# Display options
['-T', 'pdml']                 # XML output
['-T', 'json']                 # JSON output
['-T', 'ek']                   # Elasticsearch JSON
['-Y', 'http']                 # Display filter

# Decryption
['-o', 'wlan.enable_decryption:TRUE']
['-o', 'wlan.wep_key1:password']
```

### Enhanced TShark Parameters
```python
# Protocol-specific options
['-o', 'tcp.analyze_sequence_numbers:TRUE']
['-o', 'tcp.calculate_timestamps:TRUE']
['-o', 'ip.defragment:TRUE']

# Performance options
['-B', '64']                   # Buffer size (MB)
['-S']                         # Print packet summary
['-q']                         # Quiet mode

# Security options
['-o', 'tls.keylog_file:keys.log']
['-o', 'wlan.enable_decryption:TRUE']
```

## XML Output Processing

### PDML Structure
```xml
<pdml>
  <packet>
    <proto name="geninfo">
      <field name="timestamp" value="1234567890.123456"/>
      <field name="num" value="1"/>
    </proto>
    <proto name="frame">
      <field name="frame.len" value="98"/>
    </proto>
    <proto name="eth">
      <field name="eth.src" value="aa:bb:cc:dd:ee:ff"/>
      <field name="eth.dst" value="00:11:22:33:44:55"/>
    </proto>
  </packet>
</pdml>
```

### XML Parsing Logic
```python
def parse_packet_xml(xml_element):
    """Parse XML packet element into Python packet object"""
    packet_data = {}
    
    for proto in xml_element.findall('proto'):
        proto_name = proto.get('name')
        proto_data = {}
        
        for field in proto.findall('.//field'):
            field_name = field.get('name')
            field_value = field.get('value')
            field_show = field.get('show')
            
            proto_data[field_name] = {
                'value': field_value,
                'show': field_show
            }
        
        packet_data[proto_name] = proto_data
    
    return packet_data
```

## Error Handling

### TShark Execution Errors
```python
def safe_tshark_execution(command_args):
    """Execute TShark with comprehensive error handling"""
    try:
        result = tshark.get_process_result(command_args)
        
        if result.returncode != 0:
            error_msg = result.stderr.decode('utf-8')
            
            # Common TShark errors
            if "No such file" in error_msg:
                raise FileNotFoundError(f"Input file not found")
            elif "Permission denied" in error_msg:
                raise PermissionError(f"Insufficient permissions")
            elif "No interface" in error_msg:
                raise ValueError(f"Invalid network interface")
            else:
                raise RuntimeError(f"TShark error: {error_msg}")
        
        return result.stdout
        
    except FileNotFoundError:
        raise RuntimeError("TShark not found - please install Wireshark")
    except Exception as e:
        raise RuntimeError(f"TShark execution failed: {e}")
```

### XML Parsing Errors
```python
def safe_xml_parsing(xml_data):
    """Parse XML with error handling"""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_data)
        return root
        
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML data: {e}")
    except Exception as e:
        raise RuntimeError(f"XML parsing failed: {e}")
```

## Performance Optimization

### Streaming XML Processing
```python
def stream_process_packets(tshark_process):
    """Process TShark XML output in streaming fashion"""
    xml_buffer = ""
    
    for line in tshark_process.stdout:
        xml_buffer += line.decode('utf-8')
        
        # Look for complete packet
        if '</packet>' in xml_buffer:
            # Extract packet XML
            start = xml_buffer.find('<packet>')
            end = xml_buffer.find('</packet>') + 9
            
            if start >= 0 and end > start:
                packet_xml = xml_buffer[start:end]
                
                # Process packet
                yield parse_packet_xml(packet_xml)
                
                # Remove processed packet from buffer
                xml_buffer = xml_buffer[end:]
```

### Memory Management
```python
def memory_efficient_capture(pcap_file, packet_limit=None):
    """Memory-efficient packet processing"""
    command = [
        '-r', pcap_file,
        '-T', 'pdml'
    ]
    
    if packet_limit:
        command.extend(['-c', str(packet_limit)])
    
    process = tshark.get_tshark_process(command)
    
    try:
        packet_count = 0
        for packet in stream_process_packets(process):
            yield packet
            packet_count += 1
            
            # Memory cleanup every 1000 packets
            if packet_count % 1000 == 0:
                import gc
                gc.collect()
                
    finally:
        process.terminate()
```

## Integration with Enhanced Features

### Display Filter Integration
```python
from pyshark.display import WirelessFilters

def apply_display_filter(pcap_file, filter_name):
    """Apply PyShark display filter via TShark"""
    wireless = WirelessFilters()
    filter_obj = wireless.get_filter(filter_name)
    
    command = [
        '-r', pcap_file,
        '-T', 'pdml',
        '-Y', filter_obj.filter_expression
    ]
    
    result = tshark.get_process_result(command)
    return parse_xml_output(result.stdout)
```

### WPA Decryption Integration
```python
def decrypt_wpa_capture(pcap_file, ssid, password):
    """Decrypt WPA capture using TShark"""
    command = [
        '-r', pcap_file,
        '-o', 'wlan.enable_decryption:TRUE',
        '-o', f'wlan.wep_key1:wpa-pwd:{password}:{ssid}',
        '-T', 'pdml'
    ]
    
    result = tshark.get_process_result(command)
    return parse_xml_output(result.stdout)
```

## Cross-Platform Compatibility

### TShark Path Detection
```python
def find_tshark_executable():
    """Find TShark executable across platforms"""
    import shutil
    import platform
    
    system = platform.system()
    
    # Common TShark locations
    paths = []
    
    if system == "Windows":
        paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ]
    elif system == "Darwin":  # macOS
        paths = [
            "/usr/local/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark"
        ]
    else:  # Linux
        paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark"
        ]
    
    # Check PATH first
    tshark_path = shutil.which('tshark')
    if tshark_path:
        return tshark_path
    
    # Check common locations
    for path in paths:
        if os.path.exists(path):
            return path
    
    raise FileNotFoundError("TShark not found")
```

## Testing

Test TShark interface functionality:

```bash
cd tests/tshark
python -m pytest test_tshark_interface.py -v
```

## Configuration

### TShark Configuration
```python
# Global TShark settings
TSHARK_CONFIG = {
    'path': None,                    # Auto-detect
    'timeout': 30,                   # Execution timeout
    'buffer_size': 64,               # Buffer size (MB)
    'max_packets': None,             # No limit
    'output_format': 'pdml',         # XML output
    'enable_decryption': False       # WPA decryption
}
```

### Environment Variables
```bash
# Override TShark path
export PYSHARK_TSHARK_PATH="/custom/path/to/tshark"

# Set default buffer size
export PYSHARK_BUFFER_SIZE="128"

# Enable debug output
export PYSHARK_DEBUG="1"
```

## See Also

- `output_parser/` - XML parsing utilities
- `../capture/` - Capture classes that use TShark
- `../display/` - Display filters applied via TShark
- `../../tests/tshark/` - TShark interface tests