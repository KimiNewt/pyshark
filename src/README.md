# PyShark Source Code

This directory contains the core PyShark source code with enhanced display filters and WPA decryption capabilities.

## Directory Structure

```
src/
├── pyshark/              # Main PyShark package
│   ├── capture/          # Enhanced capture modules
│   ├── display/          # Display filters and analysis
│   ├── packet/           # Packet parsing and manipulation  
│   ├── tshark/           # TShark interface
│   ├── cache.py          # Caching functionality
│   ├── config.py         # Configuration management
│   └── __init__.py       # Package initialization
├── setup.py              # Package installation script
├── MANIFEST.in           # Package manifest
└── README.txt            # Basic package info
```

## Key Components

### PyShark Package (`pyshark/`)
- **capture/**: Enhanced capture classes with filtering and analysis
- **display/**: 146+ protocol-specific display filters
- **packet/**: Packet parsing, field access, and manipulation
- **tshark/**: Direct TShark interface and XML parsing

### Enhanced Features
- **Display Filters**: 30 Ethernet + 61 Wireless + 55 Bluetooth filters
- **WPA Decryption**: Automatic credential detection and decryption
- **Standalone Filtering**: Pure Python filtering without Wireshark
- **Enhanced Captures**: Security analysis, performance monitoring

## Installation

From this directory:

```bash
# Install in development mode
pip install -e .

# Or install normally
python setup.py install
```

## Usage

```python
import pyshark

# Basic capture
cap = pyshark.FileCapture('example.pcap')

# Enhanced capture with filters
from pyshark.capture import EnhancedFileCapture
enhanced_cap = EnhancedFileCapture('example.pcap')

# Display filters
from pyshark.display import WirelessFilters
wireless = WirelessFilters()
beacon_filter = wireless.get_filter('beacon_frames')
```

See the main README.md for complete usage documentation.