# PyShark Enhanced Capture Module

This module contains enhanced capture classes that extend PyShark's basic capture functionality with advanced filtering, analysis, and security features.

## Modules

### Core Capture Classes
- `file_capture.py` - Basic file capture functionality
- `live_capture.py` - Live network interface capture
- `remote_capture.py` - Remote capture via rpcapd
- `pipe_capture.py` - Pipe-based capture
- `inmem_capture.py` - In-memory capture handling

### Enhanced Capture Classes
- `enhanced_file_capture.py` - Advanced file analysis with filtering
- `super_enhanced_capture.py` - Comprehensive analysis capabilities
- `enhancements.py` - Capture enhancement utilities
- `capture.py` - Base capture interface

## Enhanced Features

### EnhancedFileCapture
Advanced file capture with multiple analysis views:

```python
from pyshark.capture import EnhancedFileCapture

# Create enhanced capture
cap = EnhancedFileCapture('network.pcap')

# Security analysis view
security_cap = cap.create_security_analyzer(
    detect_suspicious_traffic=True,
    analyze_failed_connections=True,
    export_objects={'http': '/tmp/extracted/'}
)

# Web traffic analysis  
web_cap = cap.create_web_analysis_view(
    include_headers=True,
    track_sessions=True,
    decode_content=True
)

# Performance analysis
perf_cap = cap.create_performance_analyzer(
    timing_fields=['tcp.time_delta', 'http.time'],
    slow_threshold=0.1
)
```

### SuperEnhancedCapture
Comprehensive analysis with multi-protocol support:

```python
from pyshark.capture import SuperEnhancedCapture

# Multi-protocol analysis
cap = SuperEnhancedCapture(['tcp_traffic.pcap', 'wireless.pcap'])

# Unified analysis across multiple files
results = cap.analyze_all_protocols()
security_issues = cap.detect_security_issues()
performance_metrics = cap.calculate_performance_metrics()
```

## Capture Enhancement Utilities

### Security Analysis
- **Suspicious Traffic Detection**: Identifies unusual patterns
- **Failed Connection Analysis**: Analyzes connection failures
- **Object Extraction**: Extracts HTTP objects, files, etc.
- **Certificate Analysis**: SSL/TLS certificate validation

### Performance Monitoring
- **Timing Analysis**: Packet timing and delays
- **Throughput Calculation**: Network performance metrics
- **Bottleneck Detection**: Identifies performance issues
- **Custom Metrics**: User-defined performance indicators

### Protocol Analysis
- **Multi-layer Analysis**: Cross-protocol correlation
- **Session Tracking**: Application session management
- **Content Decoding**: Protocol-specific content extraction
- **Field Correlation**: Custom field relationships

## Usage Examples

### Basic Enhanced Capture
```python
from pyshark.capture import EnhancedFileCapture

# Standard usage
cap = EnhancedFileCapture('example.pcap')
for packet in cap:
    print(f"Packet: {packet.length}")

# With display filter
cap = EnhancedFileCapture('example.pcap', 
                         display_filter='tcp.port == 443')
```

### Security Analysis Workflow
```python
# Security-focused analysis
security_cap = cap.create_security_analyzer(
    detect_suspicious_traffic=True,
    analyze_failed_connections=True,
    check_certificates=True
)

# Get security findings
findings = security_cap.get_security_findings()
for finding in findings:
    print(f"Security Issue: {finding['type']} - {finding['description']}")
```

### Performance Monitoring
```python
# Performance analysis
perf_cap = cap.create_performance_analyzer(
    timing_fields=['tcp.time_delta', 'tcp.analysis.ack_rtt'],
    calculate_throughput=True,
    slow_threshold=0.1
)

# Get performance metrics
metrics = perf_cap.get_performance_metrics()
print(f"Average RTT: {metrics['avg_rtt']}")
print(f"Throughput: {metrics['throughput']} Mbps")
```

### Multi-Protocol Analysis
```python
from pyshark.capture import SuperEnhancedCapture

# Analyze multiple files with different protocols
cap = SuperEnhancedCapture([
    'ethernet_traffic.pcap',
    'wireless_traffic.pcap', 
    'bluetooth_traffic.pcap'
])

# Unified analysis
protocol_summary = cap.get_protocol_summary()
cross_protocol_flows = cap.analyze_cross_protocol_flows()
```

## Integration with Display Filters

Enhanced captures work seamlessly with display filters:

```python
from pyshark.display import WirelessFilters
from pyshark.capture import EnhancedFileCapture

# Use wireless filters with enhanced capture
wireless = WirelessFilters()
beacon_filter = wireless.get_filter('beacon_frames')

cap = EnhancedFileCapture('wireless.pcap', 
                         display_filter=beacon_filter.filter_expression)
```

## Advanced Features

### Custom Field Extraction
```python
# Extract custom fields
cap.add_custom_field('tcp.stream', 'TCP Stream')
cap.add_custom_field('http.host', 'HTTP Host')

# Process with custom fields
for packet in cap:
    if hasattr(packet, 'tcp_stream'):
        print(f"Stream: {packet.tcp_stream}")
```

### Export Capabilities
```python
# Export analysis results
cap.export_to_csv('analysis_results.csv')
cap.export_to_json('packet_data.json')
cap.export_objects('extracted_files/')
```

## Testing

Test enhanced capture functionality:

```bash
cd tests/capture
python -m pytest test_enhanced_capture.py -v
```

## Integration

Enhanced captures integrate with:
- All PyShark display filters (`../display/`)
- Standard PyShark packet parsing (`../packet/`)
- TShark interface (`../tshark/`)
- Custom analysis workflows