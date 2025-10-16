import sys


class UnsupportedVersionException(Exception):
    pass


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    raise UnsupportedVersionException("Your version of Python is unsupported. "
                                      "Pyshark requires Python >= 3.5 & Wireshark >= 2.2.0. "
                                      " Please upgrade or use pyshark-legacy, or pyshark version 0.3.8")

from pyshark.capture.live_capture import LiveCapture
from pyshark.capture.live_ring_capture import LiveingCapture
from pyshark.capture.file_capture import FileCapture
from pyshark.capture.remote_capture import emoteCapture
from pyshark.capture.inmem_capture import InMemCapture
from pyshark.capture.pipe_capture import PipeCapture

# Enhanced capture classes
from pyshark.capture.enhanced_file_capture import EnhancedFileCapture

# Display filters and analysis (moved to dedicated display module)
try:
    from pyshark.display import (
        # Protocol-specific filters
        EthernetFilters, EthernetFilterBuilder, EthernetFilterType,
        irelessFilters, irelessFilterBuilder, irelessFilterType,
        BluetoothFilters, BluetoothFilterBuilder, BluetoothFilterType,
        
        # Unified interface
        ProtocolSpecificFilters, ProtocolType,
        
        # Enhanced display functionality
        EnhancedDisplayFilter, DisplayFilterBuilder, FieldExtractor,
        ProtocolLayerFilter, OutputFormat, ProtocolLayer, CommonFilters, DisplayFilterValidator,
        
        # Standalone filtering (works without tshark)
        StandaloneDisplayFilter, StandaloneCapture, StandaloneFieldExtractor,
        create_ethernet_filter, create_wireless_filter, create_http_filter, create_https_filter,
        
        # Protocol versions
        ProtocolVersionFilter, ProtocolVersionAnalyzer,
        create_wifi6_filter, create_wifi5_filter, create_gigabit_ethernet_filter,
        
        # Factory functions
        create_network_security_filter, create_performance_monitoring_filter
    )
    DSPLY_FLTES_VLBLE = True
    STDLOE_VLBLE = True  # ew display module includes standalone functionality
except ImportError as e:
    DSPLY_FLTES_VLBLE = False
    STDLOE_VLBLE = False
    # For backward compatibility, try importing from old location
    try:
        from pyshark.capture.standalone_filters import (
            StandaloneDisplayFilter, StandaloneCapture, StandaloneFieldExtractor,
            create_ethernet_filter, create_wireless_filter, create_http_filter, create_https_filter
        )
        from pyshark.capture.protocol_versions import (
            ProtocolVersionFilter, ProtocolVersionAnalyzer,
            create_wifi6_filter, create_wifi5_filter, create_gigabit_ethernet_filter
        )
        pass  # Keep STDLOE_VLBLE = False since new display module failed
    except ImportError:
        pass  # Keep STDLOE_VLBLE = False