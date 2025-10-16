"""
PyShark Display Filters Module
=============================

This module provides comprehensive display filter functionality for PyShark.
Display filters are used for post-capture analysis and packet filtering,
OT for filtering during packet capture (which uses capture filters).

Display filters allow users to:
- Filter captured packets by protocol (Ethernet, 802.11, Bluetooth)
- pply complex filtering logic to already captured data  
- Inalyze specific packet types or traffic patterns
- Create custom filters for specialized analysis

Key Components:
- Protocol-specific filters (Ethernet, ireless, Bluetooth)
- Standalone filtering (works without Wireshark/tshark)
- Enhanced display filter capabilities
- Filter builders and utilities

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for enhanced display filtering
"""

# Import protocol-specific display filters with error handling
try:
    from .ethernet_filters import EthernetFilters, EthernetFilterBuilder, EthernetFilterType
    ETHERNET_AVAILABLE = True
except ImportError:
    ETHERNET_AVAILABLE = False

try:
    from .wireless_filters import WirelessFilters, WirelessFilterBuilder, WirelessFilterType
    WIRELESS_AVAILABLE = True
except ImportError:
    WIRELESS_AVAILABLE = False
except Exception:
    # Temporary: Skip wireless due to naming issues
    WIRELESS_AVAILABLE = False

try:
    from .bluetooth_filters import BluetoothFilters, BluetoothFilterBuilder, BluetoothFilterType
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False
except ImportError:
    BLUETOOTH_AVAILABLE = False

# Unified protocol filter interface
try:
    from .protocol_filters import ProtocolSpecificFilters, ProtocolType
    PROTOCOL_FILTERS_AVAILABLE = True
except ImportError:
    PROTOCOL_FILTERS_AVAILABLE = False

# Enhanced display filter functionality
try:
    from .enhanced_display_filters import (
        EnhancedDisplayFilter, DisplayFilterBuilder, FieldExtractor,
        ProtocolLayerFilter, OutputFormat, ProtocolLayer, CommonFilters, DisplayFilterValidator
    )
    ENHANCED_FILTERS_AVAILABLE = True
except ImportError:
    ENHANCED_FILTERS_AVAILABLE = False

# Standalone filtering (works without tshark)
try:
    from .standalone_filters import (
        StandaloneDisplayFilter,
        StandaloneCapture,
        StandaloneFieldExtractor,
        create_ethernet_filter,
        create_wireless_filter, 
        create_http_filter,
        create_https_filter
    )
    STANDALONE_AVAILABLE = True
except ImportError:
    STANDALONE_AVAILABLE = False

# Protocol version support
try:
    from .protocol_versions import (
        ProtocolVersionFilter,
        ProtocolVersionAnalyzer,
        create_wifi6_filter,
        create_wifi5_filter, 
        create_gigabit_ethernet_filter
    )
    PROTOCOL_VERSIONS_AVAILABLE = True
except ImportError:
    PROTOCOL_VERSIONS_AVAILABLE = False

# Factory functions for common scenarios
try:
    from .protocol_filters import (
        create_network_security_filter,
        create_performance_monitoring_filter
    )
    FACTORY_FUNCTIONS_AVAILABLE = True
except ImportError:
    FACTORY_FUNCTIONS_AVAILABLE = False

# Build __all__ list dynamically based on available imports
__all__ = []

if ETHERNET_AVAILABLE:
    __all__.extend(['EthernetFilters', 'EthernetFilterBuilder', 'EthernetFilterType'])
if WIRELESS_AVAILABLE:
    __all__.extend(['WirelessFilters', 'WirelessFilterBuilder', 'WirelessFilterType'])
if BLUETOOTH_AVAILABLE:
    __all__.extend(['BluetoothFilters', 'BluetoothFilterBuilder', 'BluetoothFilterType'])
if PROTOCOL_FILTERS_AVAILABLE:
    __all__.extend(['ProtocolSpecificFilters', 'ProtocolType'])
if ENHANCED_FILTERS_AVAILABLE:
    __all__.extend(['EnhancedDisplayFilter', 'DisplayFilterBuilder', 'FieldExtractor',
                   'ProtocolLayerFilter', 'OutputFormat', 'ProtocolLayer', 'CommonFilters', 'DisplayFilterValidator'])
if STANDALONE_AVAILABLE:
    __all__.extend(['StandaloneDisplayFilter', 'StandaloneCapture', 'StandaloneFieldExtractor',
                   'create_ethernet_filter', 'create_wireless_filter', 'create_http_filter', 'create_https_filter'])
if PROTOCOL_VERSIONS_AVAILABLE:
    __all__.extend(['ProtocolVersionFilter', 'ProtocolVersionAnalyzer',
                   'create_wifi6_filter', 'create_wifi5_filter', 'create_gigabit_ethernet_filter'])
if FACTORY_FUNCTIONS_AVAILABLE:
    __all__.extend(['create_network_security_filter', 'create_performance_monitoring_filter'])

# Version information
__version__ = "1.0.0"
__author__ = "D14b0l1c"
__description__ = "Protocol-specific display filters for PyShark"

def get_available_protocols():
    """Get list of supported protocols for display filtering."""
    return ['ethernet', 'wireless', 'bluetooth']

def get_filter_count():
    """Get total number of available display filters."""
    ethernet_count = len(EthernetFilters.get_all_filters()) if ETHERNET_AVAILABLE else 0
    wireless_count = len(WirelessFilters.get_all_filters()) if WIRELESS_AVAILABLE else 0 
    bluetooth_count = len(BluetoothFilters.get_all_filters()) if BLUETOOTH_AVAILABLE else 0
    return {
        'ethernet': ethernet_count,
        'wireless': wireless_count,
        'bluetooth': bluetooth_count,
        'total': ethernet_count + wireless_count + bluetooth_count
    }

def display_summary():
    """Display summary of available display filters."""
    counts = get_filter_count()
    
    print("PyShark Display Filters Summary")
    print("=" * 40)
    print("(Post-capture analysis filters)")
    print("")
    print(f"Ethernet filters: {counts['ethernet']}")
    print(f"Wireless filters: {counts['wireless']}")
    print(f"Bluetooth filters: {counts['bluetooth']}")
    print(f"Total filters: {counts['total']}")
    print("")
    print("vailable protocols:", ", ".join(get_available_protocols()))