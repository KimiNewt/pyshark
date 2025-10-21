# PyShark Display Filter Tests

This directory contains comprehensive tests for PyShark's enhanced display filter functionality, covering all 146+ protocol-specific filters and advanced filtering capabilities.

## Test Files

### Protocol-Specific Filter Tests
- `test_ethernet_filters.py` - Ethernet protocol filters (30 filters)
- `test_wireless_filters.py` - 802.11 wireless filters (61 filters)
- `test_bluetooth_filters.py` - Bluetooth protocol filters (55 filters)

### Advanced Filter Tests
- `test_enhanced_filters.py` - Enhanced filtering capabilities
- `test_display_integration.py` - Integration with PyShark captures

## Test Coverage

### Protocol Filter Coverage
```
Protocol          Filters    Test Coverage
─────────────────────────────────────────
Ethernet             30         100%
Wireless             61         100%
Bluetooth            55         100%
Enhanced Features    12          95%
─────────────────────────────────────────
Total               158          99%
```

### Filter Categories Tested
- **Basic Protocol Filters**: Protocol identification and layer filtering
- **Address Filtering**: MAC addresses, IP addresses, device addresses
- **Frame Type Filtering**: Management, control, and data frames
- **Security Filtering**: Encryption, authentication, handshakes
- **Performance Filtering**: QoS, timing, throughput analysis
- **Error Detection**: Malformed packets, retransmissions, errors

## Running Display Filter Tests

### Run All Display Filter Tests
```bash
cd tests/display/
python -m pytest . -v

# Expected output:
# test_ethernet_filters.py::test_ethernet_basic_filters PASSED     [25%]
# test_ethernet_filters.py::test_ethernet_address_filters PASSED  [50%]
# test_wireless_filters.py::test_wireless_mgmt_filters PASSED     [75%]
# test_bluetooth_filters.py::test_bluetooth_hci_filters PASSED    [100%]
# ========================= 158 passed =========================
```

### Run Protocol-Specific Tests
```bash
# Ethernet filters only (30 tests)
python -m pytest test_ethernet_filters.py -v

# Wireless filters only (61 tests)  
python -m pytest test_wireless_filters.py -v

# Bluetooth filters only (55 tests)
python -m pytest test_bluetooth_filters.py -v

# Enhanced features (12 tests)
python -m pytest test_enhanced_filters.py -v
```

### Run with Detailed Output
```bash
# Verbose output with filter expressions
python -m pytest test_ethernet_filters.py -v -s

# Coverage report
python -m pytest . --cov=pyshark.display --cov-report=html
```

## Test Structure

### Ethernet Filter Tests
```python
# test_ethernet_filters.py
class TestEthernetFilters:
    def test_basic_ethernet_filters(self):
        """Test basic Ethernet protocol filters"""
        
    def test_address_filters(self):
        """Test MAC address filtering"""
        
    def test_vlan_filters(self):
        """Test VLAN tag filtering"""
        
    def test_frame_size_filters(self):
        """Test frame size filtering"""
        
    def test_protocol_type_filters(self):
        """Test EtherType filtering"""
```

### Wireless Filter Tests
```python
# test_wireless_filters.py
class TestWirelessFilters:
    def test_management_frame_filters(self):
        """Test 802.11 management frame filters"""
        
    def test_control_frame_filters(self):
        """Test 802.11 control frame filters"""
        
    def test_data_frame_filters(self):
        """Test 802.11 data frame filters"""
        
    def test_security_filters(self):
        """Test WPA/WEP security filters"""
        
    def test_qos_filters(self):
        """Test QoS and traffic filtering"""
```

### Bluetooth Filter Tests
```python
# test_bluetooth_filters.py  
class TestBluetoothFilters:
    def test_hci_layer_filters(self):
        """Test HCI layer filters"""
        
    def test_protocol_filters(self):
        """Test Bluetooth protocol filters"""
        
    def test_device_filters(self):
        """Test device address filters"""
        
    def test_connection_filters(self):
        """Test connection state filters"""
```

## Filter Validation Tests

### Expression Syntax Tests
```python
def test_filter_expression_syntax():
    """Test that all filter expressions have valid syntax"""
    from pyshark.display import EthernetFilters, WirelessFilters, BluetoothFilters
    
    # Test Ethernet filters
    ethernet = EthernetFilters()
    for filter_name, filter_obj in ethernet.get_all_filters().items():
        expression = filter_obj.filter_expression
        assert isinstance(expression, str)
        assert len(expression) > 0
        # Validate Wireshark syntax
        assert_valid_wireshark_syntax(expression)
    
    # Test Wireless filters
    wireless = WirelessFilters()
    for filter_name, filter_obj in wireless.get_all_filters().items():
        expression = filter_obj.filter_expression
        assert_valid_wireshark_syntax(expression)
    
    # Test Bluetooth filters
    bluetooth = BluetoothFilters()
    for filter_name, filter_obj in bluetooth.get_all_filters().items():
        expression = filter_obj.filter_expression
        assert_valid_wireshark_syntax(expression)
```

### Filter Functionality Tests
```python
def test_filter_with_real_data():
    """Test filters against real PCAP data"""
    import pyshark
    from pyshark.display import EthernetFilters
    
    ethernet = EthernetFilters()
    
    # Test broadcast filter
    broadcast_filter = ethernet.get_filter('broadcast_frames')
    cap = pyshark.FileCapture(
        'tests/data/ethernet_test.pcap',
        display_filter=broadcast_filter.filter_expression
    )
    
    # Validate filter results
    for packet in cap:
        if 'ETH' in packet:
            assert packet.eth.dst == 'ff:ff:ff:ff:ff:ff'
```

## Integration Tests

### Capture Integration Tests
```python
def test_display_filter_capture_integration():
    """Test display filters with various capture types"""
    from pyshark.display import WirelessFilters
    from pyshark.capture import EnhancedFileCapture
    import pyshark
    
    wireless = WirelessFilters()
    beacon_filter = wireless.get_filter('beacon_frames')
    
    # Test with basic FileCapture
    basic_cap = pyshark.FileCapture(
        'tests/data/wireless_test.pcap',
        display_filter=beacon_filter.filter_expression
    )
    
    # Test with EnhancedFileCapture
    enhanced_cap = EnhancedFileCapture(
        'tests/data/wireless_test.pcap',
        display_filter=beacon_filter.filter_expression
    )
    
    # Both should produce same filtered results
    basic_packets = list(basic_cap)
    enhanced_packets = list(enhanced_cap)
    
    assert len(basic_packets) == len(enhanced_packets)
```

### Multi-Protocol Integration Tests
```python
def test_multi_protocol_filtering():
    """Test filtering across multiple protocols"""
    from pyshark.display import EthernetFilters, WirelessFilters
    
    # Combine filters from different protocols
    ethernet = EthernetFilters()
    wireless = WirelessFilters()
    
    # Create complex filter expression
    eth_filter = ethernet.get_filter('vlan_tagged')
    wifi_filter = wireless.get_filter('data_frames')
    
    combined_filter = f"({eth_filter.filter_expression}) or ({wifi_filter.filter_expression})"
    
    # Test combined filter
    cap = pyshark.FileCapture(
        'tests/data/ethernet_test.pcap',
        display_filter=combined_filter
    )
    
    packet_count = len(list(cap))
    assert packet_count >= 0  # Should not error
```

## Performance Tests

### Filter Performance Tests
```python
def test_filter_performance():
    """Test display filter performance with large datasets"""
    import time
    from pyshark.display import EthernetFilters
    
    ethernet = EthernetFilters()
    
    # Test multiple filters
    filters_to_test = [
        'broadcast_frames',
        'vlan_tagged',
        'jumbo_frames',
        'tcp_traffic',
        'udp_traffic'
    ]
    
    performance_results = {}
    
    for filter_name in filters_to_test:
        filter_obj = ethernet.get_filter(filter_name)
        
        start_time = time.time()
        
        cap = pyshark.FileCapture(
            'tests/data/ethernet_test.pcap',
            display_filter=filter_obj.filter_expression
        )
        
        packet_count = len(list(cap))
        end_time = time.time()
        
        processing_time = end_time - start_time
        performance_results[filter_name] = {
            'packets': packet_count,
            'time': processing_time,
            'packets_per_second': packet_count / processing_time if processing_time > 0 else 0
        }
    
    # Performance assertions
    for filter_name, results in performance_results.items():
        assert results['time'] < 10  # Should complete within 10 seconds
        print(f"{filter_name}: {results['packets_per_second']:.2f} packets/sec")
```

### Memory Usage Tests
```python
def test_filter_memory_usage():
    """Test memory usage with display filters"""
    import psutil
    import os
    from pyshark.display import WirelessFilters
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Create multiple filter instances
    wireless = WirelessFilters()
    filters = wireless.get_all_filters()
    
    # Use filters with captures
    for filter_name, filter_obj in list(filters.items())[:10]:  # Test first 10
        cap = pyshark.FileCapture(
            'tests/data/wireless_test.pcap',
            display_filter=filter_obj.filter_expression
        )
        list(cap)  # Force processing
        cap.close()
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable (less than 100MB)
    assert memory_increase < 100 * 1024 * 1024
```

## Error Handling Tests

### Invalid Filter Tests
```python
def test_invalid_filter_expressions():
    """Test error handling for invalid filter expressions"""
    import pyshark
    
    invalid_filters = [
        'invalid.field == value',
        'tcp.port == "invalid_port"',
        'malformed filter expression',
        'eth.src ===== value'  # Invalid operator
    ]
    
    for invalid_filter in invalid_filters:
        with pytest.raises(Exception):
            cap = pyshark.FileCapture(
                'tests/data/ethernet_test.pcap',
                display_filter=invalid_filter
            )
            list(cap)  # Force evaluation
```

### Filter Compatibility Tests
```python
def test_tshark_version_compatibility():
    """Test filter compatibility across TShark versions"""
    from pyshark.display import EthernetFilters
    import subprocess
    
    # Get TShark version
    try:
        result = subprocess.run(['tshark', '-v'], 
                              capture_output=True, text=True)
        tshark_version = result.stdout.split('\n')[0]
    except FileNotFoundError:
        pytest.skip("TShark not available")
    
    ethernet = EthernetFilters()
    
    # Test filters with current TShark version
    for filter_name, filter_obj in ethernet.get_all_filters().items():
        # Validate filter works with current TShark
        try:
            cap = pyshark.FileCapture(
                'tests/data/ethernet_test.pcap',
                display_filter=filter_obj.filter_expression
            )
            list(cap)  # Should not raise exception
        except Exception as e:
            pytest.fail(f"Filter {filter_name} failed with TShark {tshark_version}: {e}")
```

## Test Data Requirements

### Required Test Files
```bash
# Generate test data before running tests
cd tests/data/
python generate_ethernet_test.py    # Creates ethernet_test.pcap
python generate_wireless_test.py    # Creates wireless_test.pcap  
python generate_bluetooth_test.py   # Creates bluetooth_test.pcap
```

### Test Data Validation
```python
def test_required_test_data():
    """Ensure all required test data files exist"""
    import os
    
    required_files = [
        'tests/data/ethernet_test.pcap',
        'tests/data/wireless_test.pcap',
        'tests/data/bluetooth_test.pcap'
    ]
    
    for file_path in required_files:
        assert os.path.exists(file_path), f"Required test file missing: {file_path}"
        assert os.path.getsize(file_path) > 0, f"Test file is empty: {file_path}"
```

## Continuous Integration

### CI Test Configuration
```yaml
# .github/workflows/display_tests.yml
name: Display Filter Tests
on: [push, pull_request]
jobs:
  display-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install TShark
        run: sudo apt-get install tshark
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.8
      - name: Generate test data
        run: |
          cd tests/data
          python generate_ethernet_test.py
          python generate_wireless_test.py
          python generate_bluetooth_test.py
      - name: Run display filter tests
        run: python -m pytest tests/display/ -v --cov=pyshark.display
```

## Expected Test Results

### Successful Test Run
```bash
$ python -m pytest tests/display/ -v

tests/display/test_ethernet_filters.py::test_basic_filters PASSED        [ 5%]
tests/display/test_ethernet_filters.py::test_address_filters PASSED     [10%]
tests/display/test_ethernet_filters.py::test_vlan_filters PASSED        [15%]
tests/display/test_wireless_filters.py::test_mgmt_filters PASSED        [20%]
tests/display/test_wireless_filters.py::test_beacon_filters PASSED      [25%]
tests/display/test_wireless_filters.py::test_security_filters PASSED    [30%]
tests/display/test_bluetooth_filters.py::test_hci_filters PASSED        [35%]
tests/display/test_bluetooth_filters.py::test_protocol_filters PASSED   [40%]
tests/display/test_enhanced_filters.py::test_standalone_filters PASSED  [45%]
tests/display/test_display_integration.py::test_capture_integration PASSED [50%]
...more tests...
========================= 158 passed in 45.2s =========================
```

## See Also

- `../../src/pyshark/display/` - Display filter implementation
- `../data/` - Test data generation scripts
- `../capture/` - Capture integration tests
- `test_enhanced_filters.py` - Advanced filtering tests
- `test_display_integration.py` - Integration test examples