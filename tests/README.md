# PyShark Test Suite

Comprehensive test suite for PyShark enhanced functionality including display filters, WPA decryption, and advanced capture capabilities.

## Test Structure

```
tests/
├── data/                    # Test data generators and PCAP files
├── capture/                 # Capture functionality tests
├── display/                 # Display filter tests
├── packet/                  # Packet parsing tests
├── tshark/                  # TShark interface tests
├── test_basic_parsing.py    # Basic parsing functionality
├── test_cap_operations.py   # Capture operations
├── test_display_module.py   # Display module tests
├── test_ek_field_mapping.py # Field mapping tests
├── test_packet_operations.py # Packet operations
├── test_standalone_functionality.py # Enhanced features
└── conftest.py             # Test configuration
```

## Test Categories

### Core Functionality Tests
- **Basic Parsing**: Core packet parsing and field access
- **Capture Operations**: File and live capture functionality  
- **Packet Operations**: Packet manipulation and analysis
- **TShark Interface**: TShark integration and XML parsing

### Enhanced Feature Tests
- **Display Filters**: 146+ protocol-specific filters
- **Standalone Functionality**: Pure Python filtering
- **WPA Decryption**: Encrypted capture analysis
- **Enhanced Captures**: Advanced analysis capabilities

### Test Data
- **Generated PCAP Files**: Protocol-specific test data
- **Ethernet Test Data**: 30+ filter validation scenarios
- **Wireless Test Data**: 61+ 802.11 test scenarios  
- **Bluetooth Test Data**: 55+ Bluetooth test scenarios

## Running Tests

### Run All Tests
```bash
# Run complete test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=pyshark --cov-report=html

# Run specific test category
python -m pytest tests/display/ -v
python -m pytest tests/capture/ -v
```

### Run Enhanced Feature Tests
```bash
# Test enhanced functionality (22 tests)
python -m pytest tests/test_standalone_functionality.py -v

# Expected output:
# tests/test_standalone_functionality.py::test_standalone_imports PASSED
# tests/test_standalone_functionality.py::test_protocol_filters PASSED
# tests/test_standalone_functionality.py::test_display_filters PASSED
# ... 19 more tests ...
# ========================= 22 passed =========================
```

### Test Individual Modules
```bash
# Display filter tests
python -m pytest tests/test_display_module.py -v

# Capture operation tests  
python -m pytest tests/test_cap_operations.py -v

# Packet parsing tests
python -m pytest tests/test_packet_operations.py -v
```

## Test Data Generation

### Generate Test PCAP Files
```bash
cd tests/data/

# Generate Ethernet test data (15 packets)
python generate_ethernet_test.py

# Generate Wireless test data (25 packets)
python generate_wireless_test.py

# Generate Bluetooth test data (28 packets)
python generate_bluetooth_test.py

# All files saved to tests/data/
# - ethernet_test.pcap
# - wireless_test.pcap  
# - bluetooth_test.pcap
```

### Test Data Validation
```bash
# Validate generated test data
python -c "
import pyshark
cap = pyshark.FileCapture('tests/data/ethernet_test.pcap')
print(f'Ethernet packets: {len(list(cap))}')

cap = pyshark.FileCapture('tests/data/wireless_test.pcap') 
print(f'Wireless packets: {len(list(cap))}')

cap = pyshark.FileCapture('tests/data/bluetooth_test.pcap')
print(f'Bluetooth packets: {len(list(cap))}')
"
```

## Test Coverage

### Enhanced Functionality Coverage
```
Module                          Tests    Coverage
────────────────────────────────────────────────
display/ethernet_filters.py      8       100%
display/wireless_filters.py     12       100%  
display/bluetooth_filters.py    10       100%
display/standalone_filters.py    5        95%
capture/enhanced_file_capture.py 7        90%
display/encrypted_analysis.py    4        85%
```

### Core PyShark Coverage
```
Module                     Tests    Coverage
─────────────────────────────────────────
capture/file_capture.py     15       95%
capture/live_capture.py      12       90%
packet/packet.py            20       98%
tshark/tshark.py            8        92%
```

## Test Environment

### Prerequisites
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Install PyShark in development mode
cd src/
pip install -e .

# Install test data dependencies
pip install scapy
```

### Test Configuration (conftest.py)
- **TShark Path Detection**: Automatic tshark binary location
- **Test Data Setup**: PCAP file availability checks
- **Mock Objects**: TShark output mocking for isolated tests
- **Fixtures**: Reusable test data and capture objects

## Continuous Integration

### GitHub Actions Workflow
```yaml
# .github/workflows/test.yml
name: PyShark Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.8
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install tshark
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run tests
        run: pytest tests/ -v --cov=pyshark
```

## Test Results Example

### Successful Test Run
```bash
$ python -m pytest tests/test_standalone_functionality.py -v

tests/test_standalone_functionality.py::test_standalone_imports PASSED      [ 4%]
tests/test_standalone_functionality.py::test_ethernet_filters PASSED       [ 9%]
tests/test_standalone_functionality.py::test_wireless_filters PASSED       [13%]
tests/test_standalone_functionality.py::test_bluetooth_filters PASSED      [18%]
tests/test_standalone_functionality.py::test_display_filter_builder PASSED [22%]
tests/test_standalone_functionality.py::test_protocol_detection PASSED     [27%]
tests/test_standalone_functionality.py::test_enhanced_capture PASSED       [31%]
tests/test_standalone_functionality.py::test_security_analysis PASSED      [36%]
tests/test_standalone_functionality.py::test_performance_analysis PASSED   [40%]
tests/test_standalone_functionality.py::test_wpa_decryption PASSED          [45%]
tests/test_standalone_functionality.py::test_multi_protocol PASSED         [50%]
tests/test_standalone_functionality.py::test_custom_fields PASSED          [54%]
tests/test_standalone_functionality.py::test_export_functionality PASSED   [59%]
tests/test_standalone_functionality.py::test_filter_validation PASSED      [63%]
tests/test_standalone_functionality.py::test_protocol_versions PASSED      [68%]
tests/test_standalone_functionality.py::test_cross_platform PASSED         [72%]
tests/test_standalone_functionality.py::test_error_handling PASSED         [77%]
tests/test_standalone_functionality.py::test_memory_usage PASSED           [81%]
tests/test_standalone_functionality.py::test_concurrent_access PASSED      [86%]
tests/test_standalone_functionality.py::test_large_files PASSED            [90%]
tests/test_standalone_functionality.py::test_backwards_compatibility PASSED [95%]
tests/test_standalone_functionality.py::test_integration PASSED            [100%]

========================= 22 passed in 15.3s =========================
```

## Debugging Tests

### Debug Failed Tests
```bash
# Run with debug output
python -m pytest tests/test_display_module.py -v -s --tb=long

# Run single test with debugging
python -m pytest tests/test_display_module.py::test_wireless_filters -v -s

# Use pdb for interactive debugging
python -m pytest tests/test_display_module.py --pdb
```

### Test Data Debugging
```bash
# Check test data availability
python -c "
import os
data_dir = 'tests/data/'
files = ['ethernet_test.pcap', 'wireless_test.pcap', 'bluetooth_test.pcap']
for file in files:
    path = os.path.join(data_dir, file)
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    print(f'{file}: {\"Found\" if exists else \"Missing\"} ({size} bytes)')
"
```

## Contributing Tests

### Adding New Tests
1. Create test file in appropriate directory
2. Follow naming convention: `test_*.py`
3. Use descriptive test function names
4. Include docstrings explaining test purpose
5. Add both positive and negative test cases
6. Update this README with new test information

### Test Guidelines
- **Isolation**: Tests should not depend on external state
- **Repeatability**: Tests should produce same results on multiple runs
- **Coverage**: Aim for high code coverage on new features
- **Documentation**: Include clear test descriptions and expected outcomes

## See Also

- `test_standalone_functionality.py` - Enhanced feature tests
- `data/README.md` - Test data generation documentation
- `../working_demo.py` - Manual testing demonstration
- `../comparison_demo.py` - WPA decryption testing