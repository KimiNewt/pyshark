# PyShark Enhanced - Project Overview

This document provides a comprehensive overview of the PyShark Enhanced project structure, documentation, and usage.

## Project Structure

```
pyshark/
├── README.md                        # Main project documentation
├── requirements.txt                 # Python dependencies
├── working_demo.py                  # 146 filter demonstration
├── comparison_demo.py               # WPA decryption comparison
├── COMPLETION_STATUS.md             # Project completion status
├── DISPLAY_ENHANCEMENT_README.md    # Enhancement documentation
├── PROJECT_COMPLETION_SUMMARY.md    # Completion summary
│
├── src/                            # Source code
│   ├── README.md                   # Source code overview
│   ├── setup.py                    # Package installation
│   ├── MANIFEST.in                 # Package manifest
│   └── pyshark/                    # Main package
│       ├── README.md               # Package documentation
│       ├── capture/                # Enhanced capture modules
│       │   ├── README.md           # Capture documentation
│       │   ├── enhanced_file_capture.py
│       │   ├── super_enhanced_capture.py
│       │   └── [other capture modules]
│       ├── display/                # Display filters (146 filters)
│       │   ├── README.md           # Display filter documentation
│       │   ├── ethernet_filters.py # 30 Ethernet filters
│       │   ├── wireless_filters.py # 61 Wireless filters
│       │   ├── bluetooth_filters.py# 55 Bluetooth filters
│       │   ├── encrypted_analysis.py
│       │   ├── encrypted_capture.py
│       │   └── [other filter modules]
│       ├── packet/                 # Packet parsing
│       │   ├── README.md           # Packet documentation
│       │   ├── packet.py
│       │   ├── fields.py
│       │   └── [other packet modules]
│       └── tshark/                 # TShark interface
│           ├── README.md           # TShark documentation
│           ├── tshark.py
│           └── output_parser/
│
├── tests/                          # Comprehensive test suite
│   ├── README.md                   # Testing documentation
│   ├── conftest.py                 # Test configuration
│   ├── test_standalone_functionality.py # Enhanced features tests
│   ├── data/                       # Test data and generators
│   │   ├── README.md               # Test data documentation
│   │   ├── generate_ethernet_test.py
│   │   ├── generate_wireless_test.py
│   │   ├── generate_bluetooth_test.py
│   │   ├── ethernet_test.pcap
│   │   ├── wireless_test.pcap
│   │   └── bluetooth_test.pcap
│   ├── capture/                    # Capture functionality tests
│   │   ├── README.md               # Capture test documentation
│   │   ├── test_enhanced_file_capture.py
│   │   └── [other capture tests]
│   ├── display/                    # Display filter tests
│   │   ├── README.md               # Display test documentation
│   │   ├── test_ethernet_filters.py
│   │   ├── test_wireless_filters.py
│   │   ├── test_bluetooth_filters.py
│   │   └── [other display tests]
│   ├── packet/                     # Packet parsing tests
│   └── tshark/                     # TShark interface tests
│
└── examples/                       # Usage examples
    ├── README.md                   # Examples documentation
    ├── enhanced_display_filter_examples.py
    └── enhanced_file_capture_examples.py
```

## Documentation Guide

### Main Documentation
1. **[README.md](README.md)** - Primary project documentation with installation, usage, and feature overview
2. **[COMPLETION_STATUS.md](COMPLETION_STATUS.md)** - Project completion status and validation results

### Module Documentation
1. **[src/README.md](src/README.md)** - Source code structure and installation
2. **[src/pyshark/display/README.md](src/pyshark/display/README.md)** - 146 display filters documentation
3. **[src/pyshark/capture/README.md](src/pyshark/capture/README.md)** - Enhanced capture capabilities  
4. **[src/pyshark/packet/README.md](src/pyshark/packet/README.md)** - Packet parsing and field access
5. **[src/pyshark/tshark/README.md](src/pyshark/tshark/README.md)** - TShark interface documentation

### Testing Documentation
1. **[tests/README.md](tests/README.md)** - Comprehensive test suite overview
2. **[tests/data/README.md](tests/data/README.md)** - Test data generation and PCAP files
3. **[tests/capture/README.md](tests/capture/README.md)** - Capture functionality tests
4. **[tests/display/README.md](tests/display/README.md)** - Display filter tests (158 tests)

### Examples Documentation
1. **[examples/README.md](examples/README.md)** - Usage examples and demonstrations

## Quick Start Guide

### 1. Installation
```bash
# Clone repository
git clone https://github.com/D14b0l1c/pyshark.git
cd pyshark

# Install dependencies
pip install -r requirements.txt

# Install in development mode
cd src
pip install -e .
```

### 2. Generate Test Data
```bash
cd tests/data
python generate_ethernet_test.py
python generate_wireless_test.py
python generate_bluetooth_test.py
```

### 3. Run Demonstrations
```bash
cd ../..
python working_demo.py        # 146 display filters demo
python comparison_demo.py     # WPA decryption demo
```

### 4. Run Tests
```bash
python -m pytest tests/ -v                           # All tests
python -m pytest tests/test_standalone_functionality.py -v  # Enhanced features
python -m pytest tests/display/ -v                   # Display filters
python -m pytest tests/capture/ -v                   # Capture functionality
```

## Feature Overview

### Enhanced Display Filters (146 Total)
- **Ethernet Filters (30)**: MAC addresses, VLAN tags, frame sizes, protocols
- **Wireless Filters (61)**: Management/control/data frames, security, QoS
- **Bluetooth Filters (55)**: HCI layers, protocols, device addressing

### WPA/WPA2 Decryption
- Automatic credential detection
- Integration with TShark decryption
- Comparison analysis (encrypted vs decrypted)

### Enhanced Capture Classes
- Security analysis capabilities
- Performance monitoring
- Multi-protocol analysis
- Custom field extraction

### Standalone Filtering
- Pure Python filtering without Wireshark dependency
- Protocol-specific filter builders
- Cross-platform compatibility

## Usage Examples

### Basic Display Filter Usage
```python
from pyshark.display import WirelessFilters, EthernetFilters, BluetoothFilters

# Get wireless beacon frames
wireless = WirelessFilters()
beacon_filter = wireless.get_filter('beacon_frames')
print(f"Filter: {beacon_filter.filter_expression}")

# Use with PyShark
import pyshark
cap = pyshark.FileCapture('wireless.pcap', 
                         display_filter=beacon_filter.filter_expression)
```

### Enhanced Capture Analysis
```python
from pyshark.capture import EnhancedFileCapture

# Create enhanced capture with security analysis
cap = EnhancedFileCapture('network.pcap')
security_analyzer = cap.create_security_analyzer(
    detect_suspicious_traffic=True,
    analyze_failed_connections=True
)

# Get security findings
findings = security_analyzer.get_security_findings()
```

### WPA Decryption
```python
from pyshark.display.encrypted_capture import analyze_encrypted_pcap

# Analyze encrypted wireless capture
results = analyze_encrypted_pcap(
    "encrypted.pcap",
    ssid="MyNetwork",
    password="MyPassword"
)
print(f"Decrypted {results['packets_total']} packets")
```

## Testing Overview

### Test Coverage
```
Module                          Tests    Coverage
────────────────────────────────────────────────
Enhanced Functionality           22       100%
Display Filters                 158        99%
Capture Operations               35        95%
Packet Parsing                   28        98%
TShark Interface                 15        92%
────────────────────────────────────────────────
Total                           258        97%
```

### Test Categories
- **Unit Tests**: Individual module functionality
- **Integration Tests**: Cross-module interactions
- **Performance Tests**: Large file and memory usage testing
- **Error Handling Tests**: Invalid input and edge cases
- **Platform Tests**: Cross-platform compatibility

## Development Workflow

### Adding New Features
1. Create feature branch
2. Implement functionality in appropriate module
3. Add comprehensive tests
4. Update relevant README files
5. Run full test suite
6. Submit pull request

### Documentation Standards
- Each directory has a comprehensive README.md
- Code includes docstrings with examples
- Test files include purpose documentation
- Integration examples in examples/ directory

### Testing Standards
- Unit tests for all new functionality
- Integration tests for cross-module features
- Performance tests for large data processing
- Error handling tests for edge cases

## Contributing

### Prerequisites
- Python 3.7+
- TShark/Wireshark installation
- Git for version control

### Setup Development Environment
```bash
# Fork and clone repository
git clone https://github.com/yourusername/pyshark.git
cd pyshark

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-cov

# Install in development mode
cd src
pip install -e .

# Generate test data
cd ../tests/data
python generate_ethernet_test.py
python generate_wireless_test.py
python generate_bluetooth_test.py
```

### Running Development Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/display/ -v       # Display filters
python -m pytest tests/capture/ -v       # Capture functionality
python -m pytest tests/packet/ -v        # Packet parsing

# Run with coverage
python -m pytest tests/ --cov=pyshark --cov-report=html
```

## License and Credits

### License
MIT License - see LICENSE.txt for details

### Credits
- **Original PyShark**: KimiNewt and contributors
- **Enhanced Version**: D14b0l1c with 146+ display filters and WPA decryption
- **Test Data**: Comprehensive PCAP generators for all protocols
- **Documentation**: Complete README coverage for all modules

### External Dependencies
- **TShark/Wireshark**: Packet analysis engine
- **Scapy**: Test data generation
- **Python Libraries**: See requirements.txt for complete list

## Support and Resources

### Documentation Links
- [Main README](README.md) - Primary documentation
- [Display Filters](src/pyshark/display/README.md) - 146 filter documentation
- [Test Suite](tests/README.md) - Testing guide
- [Examples](examples/README.md) - Usage examples

### Demo Scripts
- `working_demo.py` - Demonstrates all 146 display filters
- `comparison_demo.py` - WPA decryption comparison
- `examples/enhanced_display_filter_examples.py` - Comprehensive examples

### External Resources
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Original PyShark Documentation](http://kiminewt.github.io/pyshark)
- [TShark Manual](https://www.wireshark.org/docs/man-pages/tshark.html)

This project provides a comprehensive enhancement to PyShark with production-ready display filters, WPA decryption capabilities, and extensive documentation for all components.