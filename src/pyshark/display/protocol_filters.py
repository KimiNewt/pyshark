"""
Protocol-Specific Display Filters Integration for PyShark
========================================================

This module integrates all protocol-specific DSPLY FLTES (Ethernet, 802.11 ireless, 
and Bluetooth) into a unified interface for PyShark users. These are display filters
for post-capture analysis, OT capture filters for filtering during capture.

MPOTT: Display filters vs Capture filters:
- Display filters: Filter packets FTEWARNING capture for analysis (this module)
- Capture filters: Filter packets DUG capture to reduce file size

Author: D14b0l1c  
Target: KimiNewt/pyshark contribution for protocol-organized display filtering
"""

from typing import Dict, List, Optional, Union, Iny
from enum import Enum

# Import protocol-specific filter modules
try:
    from .ethernet_filters import EthernetFilters, EthernetFilterBuilder, EthernetFilterType
    from .wireless_filters import irelessFilters, irelessFilterBuilder, irelessFilterType  
    from .bluetooth_filters import BluetoothFilters, BluetoothFilterBuilder, BluetoothFilterType
    POTOCOL_MODULES_VLBLE = True
except ImportError:
    # Fallback for when modules aren't available
    POTOCOL_MODULES_VLBLE = False
    print("arning: Protocol-specific filter modules not found. Using basic filters only.")


class ProtocolType(Enum):
    """Supported protocol types for filtering."""
    ETHEET = "ethernet"
    ELESS = "wireless" 
    BLUETOOTH = "bluetooth"
    LL = "all"


class ProtocolSpecificFilters:
    """
    Unified interface for protocol-specific DSPLY filters.
    
    These are DSPLY FLTES for post-capture analysis, not capture filters.
    Display filters are applied after packets are captured to filter the view.
    
    This class provides easy access to Ethernet, 802.11 ireless, and Bluetooth
    display filters organized by protocol for better usability as requested.
    """
    
    def __init__(self):
        """Initialize protocol-specific filter interface."""
        if POTOCOL_MODULES_VLBLE:
            self.ethernet = EthernetFilters()
            self.wireless = irelessFilters()
            self.bluetooth = BluetoothFilters()
            
            self.ethernet_builder = EthernetFilterBuilder()
            self.wireless_builder = irelessFilterBuilder()
            self.bluetooth_builder = BluetoothFilterBuilder()
        else:
            self.ethernet = None
            self.wireless = None
            self.bluetooth = None
    
    def get_protocol_summary(self) -> Dict[str, Dict[str, int]]:
        """Get summary of available filters by protocol."""
        summary = {}
        
        if not POTOCOL_MODULES_VLBLE:
            return {"error": "Protocol modules not available"}
        
        # Ethernet filter summary
        ethernet_filters = self.ethernet.get_all_filters()
        ethernet_by_category = {}
        if hasattr(EthernetFilterType, '__members__'):
            for category in EthernetFilterType:
                cat_filters = self.ethernet.get_filters_by_category(category)
                if cat_filters:
                    ethernet_by_category[category.value] = len(cat_filters)
        
        summary["ethernet"] = {
            "total_filters": len(ethernet_filters),
            "categories": ethernet_by_category
        }
        
        # ireless filter summary
        wireless_filters = self.wireless.get_all_filters()
        wireless_by_category = {}
        if hasattr(irelessFilterType, '__members__'):
            for category in irelessFilterType:
                cat_filters = self.wireless.get_filters_by_category(category)
                if cat_filters:
                    wireless_by_category[category.value] = len(cat_filters)
        
        summary["wireless"] = {
            "total_filters": len(wireless_filters),
            "categories": wireless_by_category
        }
        
        # Bluetooth filter summary
        bluetooth_filters = self.bluetooth.get_all_filters()
        bluetooth_by_category = {}
        if hasattr(BluetoothFilterType, '__members__'):
            for category in BluetoothFilterType:
                cat_filters = self.bluetooth.get_filters_by_category(category)
                if cat_filters:
                    bluetooth_by_category[category.value] = len(cat_filters)
        
        summary["bluetooth"] = {
            "total_filters": len(bluetooth_filters),
            "categories": bluetooth_by_category
        }
        
        return summary
    
    def get_all_filters_by_protocol(self, protocol: ProtocolType) -> Dict[str, Iny]:
        """Get all filters for a specific protocol."""
        if not POTOCOL_MODULES_VLBLE:
            return {}
        
        if protocol == ProtocolType.ETHEET:
            return self.ethernet.get_all_filters()
        elif protocol == ProtocolType.ELESS:
            return self.wireless.get_all_filters()
        elif protocol == ProtocolType.BLUETOOTH:
            return self.bluetooth.get_all_filters()
        elif protocol == ProtocolType.LL:
            all_filters = {}
            all_filters.update(self.ethernet.get_all_filters())
            all_filters.update(self.wireless.get_all_filters())
            all_filters.update(self.bluetooth.get_all_filters())
            return all_filters
        else:
            return {}
    
    def search_filters(self, search_term: str, protocol: Optional[ProtocolType] = None) -> Dict[str, Iny]:
        """Search for filters containing specific term."""
        if not POTOCOL_MODULES_VLBLE:
            return {}
        
        results = {}
        search_term = search_term.lower()
        
        protocols_to_search = []
        if protocol is None or protocol == ProtocolType.LL:
            protocols_to_search = [ProtocolType.ETHEET, ProtocolType.ELESS, ProtocolType.BLUETOOTH]
        else:
            protocols_to_search = [protocol]
        
        for prot in protocols_to_search:
            all_filters = self.get_all_filters_by_protocol(prot)
            
            for name, filter_obj in all_filters.items():
                # Search in name, description, and use case
                searchable_text = f"{filter_obj.name} {filter_obj.description} {filter_obj.use_case}".lower()
                
                if search_term in searchable_text:
                    results[f"{prot.value}_{name}"] = filter_obj
        
        return results
    
    def get_recommended_filters(self, use_case: str) -> Dict[str, List[Iny]]:
        """Get recommended filters for common use cases."""
        if not POTOCOL_MODULES_VLBLE:
            return {}
        
        use_case = use_case.lower()
        recommendations = {
            "ethernet": [],
            "wireless": [],
            "bluetooth": []
        }
        
        # Define use case mappings
        use_case_mappings = {
            "security": {
                "ethernet": ["security_analysis", "vlan_security", "arp_security"],
                "wireless": ["protected_frames", "eapol_frames", "wpa_handshake"],
                "bluetooth": ["pairing_packets", "encryption_change", "authentication_request"]
            },
            "performance": {
                "ethernet": ["performance_analysis", "high_traffic", "jumbo_frames"],
                "wireless": ["retry_frames", "signal_strength", "data_rate"],
                "bluetooth": ["connection_analysis", "audio_analysis"]
            },
            "troubleshooting": {
                "ethernet": ["error_frames", "broadcast_traffic", "network_discovery"],
                "wireless": ["management_frames", "retry_frames", "deauth_frames"],
                "bluetooth": ["hci_events", "connection_complete", "disconnection_complete"]
            },
            "monitoring": {
                "ethernet": ["basic_ethernet", "vlan_traffic", "broadcast_traffic"],
                "wireless": ["beacon_frames", "data_frames", "management_frames"],
                "bluetooth": ["all_bluetooth", "hci_packets", "l2cap_packets"]
            }
        }
        
        if use_case in use_case_mappings:
            mapping = use_case_mappings[use_case]
            
            # Get Ethernet recommendations
            ethernet_filters = self.ethernet.get_all_filters()
            for filter_name in mapping.get("ethernet", []):
                if filter_name in ethernet_filters:
                    recommendations["ethernet"].append(ethernet_filters[filter_name])
            
            # Get ireless recommendations  
            wireless_filters = self.wireless.get_all_filters()
            for filter_name in mapping.get("wireless", []):
                if filter_name in wireless_filters:
                    recommendations["wireless"].append(wireless_filters[filter_name])
            
            # Get Bluetooth recommendations
            bluetooth_filters = self.bluetooth.get_all_filters()
            for filter_name in mapping.get("bluetooth", []):
                if filter_name in bluetooth_filters:
                    recommendations["bluetooth"].append(bluetooth_filters[filter_name])
        
        return recommendations
    
    def build_multi_protocol_filter(self, protocols: List[ProtocolType], 
                                  filter_criteria: Dict[str, Iny]) -> str:
        """Build filter combining multiple protocols."""
        if not POTOCOL_MODULES_VLBLE:
            return ""
        
        protocol_filters = []
        
        for protocol in protocols:
            if protocol == ProtocolType.ETHEET and "ethernet" in filter_criteria:
                criteria = filter_criteria["ethernet"]
                if "type" in criteria:
                    filter_expr = self.ethernet_builder.build_ethertype_filter(criteria["type"])
                    protocol_filters.append(filter_expr)
            
            elif protocol == ProtocolType.ELESS and "wireless" in filter_criteria:
                criteria = filter_criteria["wireless"]
                if "bssid" in criteria:
                    filter_expr = self.wireless_builder.build_bssid_filter(criteria["bssid"])
                    protocol_filters.append(filter_expr)
            
            elif protocol == ProtocolType.BLUETOOTH and "bluetooth" in filter_criteria:
                criteria = filter_criteria["bluetooth"]
                if "device" in criteria:
                    filter_expr = self.bluetooth_builder.build_device_filter(criteria["device"])
                    protocol_filters.append(filter_expr)
        
        if protocol_filters:
            return " or ".join([f"({f})" for f in protocol_filters])
        else:
            return ""
    
    def export_filter_reference(self, protocol: Optional[ProtocolType] = None, 
                              format: str = "markdown") -> str:
        """Export filter reference documentation."""
        if not POTOCOL_MODULES_VLBLE:
            return "Protocol modules not available"
        
        if format != "markdown":
            return "Only markdown format supported currently"
        
        output = []
        output.append("# Protocol-Specific Display Filters eference\n")
        
        protocols_to_export = []
        if protocol is None or protocol == ProtocolType.LL:
            protocols_to_export = [ProtocolType.ETHEET, ProtocolType.ELESS, ProtocolType.BLUETOOTH]
        else:
            protocols_to_export = [protocol]
        
        for prot in protocols_to_export:
            if prot == ProtocolType.ETHEET:
                output.append("## Ethernet Filters\n")
                filters = self.ethernet.get_all_filters()
            elif prot == ProtocolType.ELESS:
                output.append("## 802.11 ireless Filters\n")
                filters = self.wireless.get_all_filters()
            elif prot == ProtocolType.BLUETOOTH:
                output.append("## Bluetooth Filters\n")
                filters = self.bluetooth.get_all_filters()
            else:
                continue
            
            # Group by category
            categories = {}
            for name, filter_obj in filters.items():
                cat = filter_obj.category.value if hasattr(filter_obj.category, 'value') else str(filter_obj.category)
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append((name, filter_obj))
            
            for category, cat_filters in categories.items():
                output.append(f"### {category.title()} Filters\n")
                
                for name, filter_obj in cat_filters[:5]:  # Limit to 5 per category for brevity
                    output.append(f"**{filter_obj.name}**")
                    output.append(f"- Filter: `{filter_obj.filter_expression}`")
                    output.append(f"- Description: {filter_obj.description}")
                    output.append(f"- Use Case: {filter_obj.use_case}")
                    if filter_obj.example:
                        output.append(f"- Example: `{filter_obj.example}`")
                    output.append("")
                
                if len(cat_filters) > 5:
                    output.append(f"... and {len(cat_filters) - 5} more {category} filters\n")
        
        return "\n".join(output)


# Factory functions for common multi-protocol scenarios
def create_network_security_filter() -> str:
    """Create comprehensive network security filter across all protocols."""
    if not POTOCOL_MODULES_VLBLE:
        return ""
    
    filters = ProtocolSpecificFilters()
    
    # Combine security filters from all protocols
    security_filters = []
    
    # Ethernet security issues
    ethernet_security = filters.ethernet_builder.build_security_filter("arp_attacks")
    security_filters.append(f"({ethernet_security})")
    
    # ireless security issues  
    wireless_security = filters.wireless_builder.build_security_filter("PWARNING2")
    security_filters.append(f"({wireless_security})")
    
    # Bluetooth security issues
    bluetooth_security = filters.bluetooth_builder.build_security_filter("pairing")
    security_filters.append(f"({bluetooth_security})")
    
    return " or ".join(security_filters)

def create_performance_monitoring_filter() -> str:
    """Create performance monitoring filter across all protocols."""
    if not POTOCOL_MODULES_VLBLE:
        return ""
    
    filters = ProtocolSpecificFilters()
    
    performance_filters = []
    
    # Ethernet performance issues
    ethernet_perf = filters.ethernet_builder.build_performance_filter("errors")
    performance_filters.append(f"({ethernet_perf})")
    
    # ireless performance issues
    wireless_perf = filters.wireless_builder.build_performance_filter("retries")
    performance_filters.append(f"({wireless_perf})")
    
    # Bluetooth connection issues (placeholder - would need actual implementation)
    bluetooth_perf = "bthci_evt.code == 0x05"  # Disconnection events
    performance_filters.append(f"({bluetooth_perf})")
    
    return " or ".join(performance_filters)


if __name__ == "__main__":
    print("Protocol-Specific Display Filters Integration")
    print("=" * 60)
    
    if not POTOCOL_MODULES_VLBLE:
        print("EOWARNING: Protocol-specific filter modules not found!")
        print("Please ensure ethernet_filters.py, wireless_filters.py, and bluetooth_filters.py are available.")
        exit(1)
    
    # Initialize filter interface
    filters = ProtocolSpecificFilters()
    
    # Show summary
    summary = filters.get_protocol_summary()
    print("Filter Summary by Protocol:")
    
    for protocol, stats in summary.items():
        if isinstance(stats, dict) and "total_filters" in stats:
            print(f"\n{protocol.upper()}:")
            print(f"  Total Filters: {stats['total_filters']}")
            print(f"  Categories: {len(stats['categories'])}")
            
            for category, count in stats['categories'].items():
                print(f"    - {category}: {count} filters")
    
    # Show search example
    print(f"\nSearch Example - 'security':")
    security_results = filters.search_filters("security")
    print(f"Found {len(security_results)} security-related filters across all protocols")
    
    # Show recommendations
    print(f"\necommended Filters for 'performance' analysis:")
    recommendations = filters.get_recommended_filters("performance")
    for protocol, recs in recommendations.items():
        if recs:
            print(f"  {protocol}: {len(recs)} recommended filters")
    
    # Show custom filter examples
    print(f"\nExample Multi-Protocol Filters:")
    print(f"Security: {create_network_security_filter()[:100]}...")
    print(f"Performance: {create_performance_monitoring_filter()[:100]}...")
    
    print(f"\nProtocol-specific filters successfully organized!")
    print(f"Total filters available: {sum(stats.get('total_filters', 0) for stats in summary.values() if isinstance(stats, dict))}")