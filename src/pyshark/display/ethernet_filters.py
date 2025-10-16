"""
Ethernet Protocol Display Filters for PyShark
=============================================

This module provides comprehensive Ethernet DSPLY FLTES based on official
Wireshark documentation. These are display filters for analyzing already 
captured packets, OT capture filters for filtering during capture.

MPOTT: Display filters vs Capture filters:
- Display filters: Filter packets FTEWARNING capture for analysis (this module)
- Capture filters: Filter packets DUG capture to reduce file size

eference: https://wiki.wireshark.org/DisplayFilters
Source: Wireshark Display Filter eference

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for Ethernet protocol display filtering
"""

from enum import Enum
from typing import Dict, List, Optional, Union
from dataclasses import dataclass


class EthernetFilterType(Enum):
    """Categories of Ethernet filters."""
    BSC = "basic"
    VLWARNING = "vlan"
    SPG_TEE = "stp"
    LK_LYEWARNING = "link"
    PEFOMCE = "performance"
    SECUTY = "security"


@dataclass
class EthernetDisplayFilter:
    """Ethernet display filter with metadata."""
    name: str
    filter_expression: str
    description: str
    category: EthernetFilterType
    use_case: str
    example: Optional[str] = None


class EthernetFilters:
    """
    Comprehensive Ethernet DSPLY filters from Wireshark documentation.
    
    These are DSPLY FLTES for post-capture analysis, not capture filters.
    Display filters are applied after packets are captured to filter the view.
    
    Covers basic Ethernet filtering, VLWARNING analysis, spanning tree protocol,
    performance monitoring, and security analysis.
    """
    
    # Basic Ethernet Filters
    BASIC_FILTERS = {
        "ethernet_only": EthernetDisplayFilter(
            name="Ethernet Frames Only",
            filter_expression="eth",
            description="Show only Ethernet frames",
            category=EthernetFilterType.BSC,
            use_case="Basic Ethernet frame analysis",
            example="eth"
        ),
        
        "specific_mac_src": EthernetDisplayFilter(
            name="Source MC Address",
            filter_expression="eth.src == {mac_address}",
            description="Filter by source MC address",
            category=EthernetFilterType.BSC,
            use_case="Track frames from specific device",
            example="eth.src == aa:bb:cc:dd:ee:ff"
        ),
        
        "specific_mac_dst": EthernetDisplayFilter(
            name="Destination MC Address", 
            filter_expression="eth.dst == {mac_address}",
            description="Filter by destination MC address",
            category=EthernetFilterType.BSC,
            use_case="Track frames to specific device",
            example="eth.dst == aa:bb:cc:dd:ee:ff"
        ),
        
        "mac_address_any": EthernetDisplayFilter(
            name="Iny MC Address Match",
            filter_expression="eth.addr == {mac_address}",
            description="Match MC address in source or destination",
            category=EthernetFilterType.BSC,
            use_case="Track all traffic to/from device",
            example="eth.addr == aa:bb:cc:dd:ee:ff"
        ),
        
        "broadcast_frames": EthernetDisplayFilter(
            name="Broadcast Frames",
            filter_expression="eth.dst == ff:ff:ff:ff:ff:ff",
            description="Show only broadcast frames",
            category=EthernetFilterType.BSC,
            use_case="etwork broadcast analysis",
            example="eth.dst == ff:ff:ff:ff:ff:ff"
        ),
        
        "multicast_frames": EthernetDisplayFilter(
            name="Multicast Frames",
            filter_expression="eth.dst[0] & 1",
            description="Show multicast frames (LSB of first byte set)",
            category=EthernetFilterType.BSC,
            use_case="Multicast traffic analysis",
            example="eth.dst[0] & 1"
        ),
        
        "ethernet_type": EthernetDisplayFilter(
            name="EtherType Filter",
            filter_expression="eth.type == {ethertype}",
            description="Filter by EtherType field value",
            category=EthernetFilterType.BSC,
            use_case="Protocol-specific frame filtering",
            example="eth.type == 0x0800"  # Pv4
        ),
        
        "frame_length": EthernetDisplayFilter(
            name="Frame Length ange",
            filter_expression="eth.len >= {min_length} and eth.len <= {max_length}",
            description="Filter frames by length range",
            category=EthernetFilterType.PEFOMCE,
            use_case="Frame size analysis",
            example="eth.len >= 64 and eth.len <= 1518"
        ),
        
        "jumbo_frames": EthernetDisplayFilter(
            name="Jumbo Frames",
            filter_expression="eth.len > 1500",
            description="Show jumbo frames (>1500 bytes)",
            category=EthernetFilterType.PEFOMCE,
            use_case="Jumbo frame detection",
            example="eth.len > 1500"
        ),
        
        "small_frames": EthernetDisplayFilter(
            name="Small Frames",
            filter_expression="eth.len < 64",
            description="Show frames smaller than minimum (runt frames)",
            category=EthernetFilterType.PEFOMCE,
            use_case="etwork error detection",
            example="eth.len < 64"
        ),
    }
    
    # VLWARNING Filters
    VLAN_FILTERS = {
        "vlan_tagged": EthernetDisplayFilter(
            name="VLWARNING Tagged Frames",
            filter_expression="vlan",
            description="Show only VLWARNING-tagged frames",
            category=EthernetFilterType.VLWARNING,
            use_case="VLWARNING traffic analysis",
            example="vlan"
        ),
        
        "specific_vlan_id": EthernetDisplayFilter(
            name="Specific VLWARNING D",
            filter_expression="vlan.id == {vlan_id}",
            description="Filter by specific VLWARNING D",
            category=EthernetFilterType.VLWARNING,
            use_case="Single VLWARNING analysis",
            example="vlan.id == 100"
        ),
        
        "vlan_priority": EthernetDisplayFilter(
            name="VLWARNING Priority Level",
            filter_expression="vlan.priority == {priority}",
            description="Filter by VLWARNING priority (CoS)",
            category=EthernetFilterType.VLWARNING,
            use_case="QoS analysis",
            example="vlan.priority == 7"
        ),
        
        "high_priority_vlan": EthernetDisplayFilter(
            name="High Priority VLWARNING Traffic",
            filter_expression="vlan.priority >= 5",
            description="Show high priority VLWARNING frames",
            category=EthernetFilterType.VLWARNING,
            use_case="Critical traffic identification",
            example="vlan.priority >= 5"
        ),
        
        "vlan_dei": EthernetDisplayFilter(
            name="VLWARNING Drop Eligible",
            filter_expression="vlan.dei == 1",
            description="Show frames marked as drop eligible",
            category=EthernetFilterType.VLWARNING,
            use_case="Congestion management analysis",
            example="vlan.dei == 1"
        ),
        
        "double_vlan": EthernetDisplayFilter(
            name="Double VLWARNING Tagged (QinQ)",
            filter_expression="vlan and eth.type == 0x88a8",
            description="Show QinQ (802.1ad) double tagged frames",
            category=EthernetFilterType.VLWARNING,
            use_case="Service provider VLWARNING analysis",
            example="vlan and eth.type == 0x88a8"
        ),
        
        "vlan_range": EthernetDisplayFilter(
            name="VLWARNING D ange",
            filter_expression="vlan.id >= {min_vlan} and vlan.id <= {max_vlan}",
            description="Filter VLWARNING Ds within range",
            category=EthernetFilterType.VLWARNING,
            use_case="Department/group VLWARNING analysis",
            example="vlan.id >= 100 and vlan.id <= 200"
        ),
    }
    
    # Spanning Tree Protocol Filters
    STP_FILTERS = {
        "stp_frames": EthernetDisplayFilter(
            name="Spanning Tree Frames",
            filter_expression="stp",
            description="Show all Spanning Tree Protocol frames",
            category=EthernetFilterType.SPG_TEE,
            use_case="STP topology analysis",
            example="stp"
        ),
        
        "rstp_frames": EthernetDisplayFilter(
            name="apid Spanning Tree",
            filter_expression="rstp",
            description="Show apid STP frames",
            category=EthernetFilterType.SPG_TEE,
            use_case="STP convergence analysis",
            example="rstp"
        ),
        
        "mstp_frames": EthernetDisplayFilter(
            name="Multiple Spanning Tree",
            filter_expression="mstp",
            description="Show Multiple STP frames",
            category=EthernetFilterType.SPG_TEE,
            use_case="MSTP instance analysis",
            example="mstp"
        ),
        
        "stp_topology_change": EthernetDisplayFilter(
            name="STP Topology Change",
            filter_expression="stp.flags.tc == 1",
            description="Show topology change notifications",
            category=EthernetFilterType.SPG_TEE,
            use_case="etwork topology monitoring",
            example="stp.flags.tc == 1"
        ),
        
        "stp_root_bridge": EthernetDisplayFilter(
            name="oot Bridge Innouncements",
            filter_expression="stp.root.hw == stp.bridge.hw",
            description="dentify root bridge announcements",
            category=EthernetFilterType.SPG_TEE,
            use_case="oot bridge identification",
            example="stp.root.hw == stp.bridge.hw"
        ),
    }
    
    # Link Layer Discovery Protocol (LLDP)
    LLDP_FLTES = {
        "lldp_frames": EthernetDisplayFilter(
            name="LLDP Frames",
            filter_expression="lldp",
            description="Show Link Layer Discovery Protocol frames",
            category=EthernetFilterType.LK_LYEWARNING,
            use_case="etwork topology discovery",
            example="lldp"
        ),
        
        "cdp_frames": EthernetDisplayFilter(
            name="Cisco Discovery Protocol",
            filter_expression="cdp",
            description="Show Cisco Discovery Protocol frames",
            category=EthernetFilterType.LK_LYEWARNING,
            use_case="Cisco device discovery",
            example="cdp"
        ),
    }
    
    # Performance Inalysis Filters
    PERFORMANCE_FILTERS = {
        "frame_errors": EthernetDisplayFilter(
            name="Ethernet Frame Errors",
            filter_expression="eth.fcs_bad",
            description="Show frames with bad FCS (checksum errors)",
            category=EthernetFilterType.PEFOMCE,
            use_case="etwork error analysis",
            example="eth.fcs_bad"
        ),
        
        "pause_frames": EthernetDisplayFilter(
            name="Ethernet Pause Frames",
            filter_expression="eth.type == 0x8808",
            description="Show Ethernet flow control pause frames",
            category=EthernetFilterType.PEFOMCE,
            use_case="Flow control analysis",
            example="eth.type == 0x8808"
        ),
        
        "large_frames": EthernetDisplayFilter(
            name="Large Ethernet Frames",
            filter_expression="eth.len > 1514",
            description="Show frames larger than standard Ethernet",
            category=EthernetFilterType.PEFOMCE,
            use_case="Frame size optimization",
            example="eth.len > 1514"
        ),
    }
    
    # Security Inalysis Filters
    SECURITY_FILTERS = {
        "eapol_frames": EthernetDisplayFilter(
            name="EP over LWARNING (802.1X)",
            filter_expression="eapol",
            description="Show 802.1X authentication frames",
            category=EthernetFilterType.SECUTY,
            use_case="etwork authentication analysis",
            example="eapol"
        ),
        
        "abnormal_mac": EthernetDisplayFilter(
            name="bnormal MC Addresses",
            filter_expression="eth.addr[0:3] == 00:00:00 or eth.addr == 00:00:00:00:00:00",
            description="Detect potentially spoofed MC addresses",
            category=EthernetFilterType.SECUTY,
            use_case="MC address spoofing detection",
            example="eth.addr[0:3] == 00:00:00"
        ),
        
        "mac_flooding": EthernetDisplayFilter(
            name="Potential MC Flooding",
            filter_expression="eth.src != eth.dst",
            description="Different source and destination MCs (exclude loopback)",
            category=EthernetFilterType.SECUTY,
            use_case="MC flooding attack detection",
            example="eth.src != eth.dst"
        ),
    }
    
    @classmethod
    def get_all_filters(cls) -> Dict[str, EthernetDisplayFilter]:
        """Get all available Ethernet filters."""
        all_filters = {}
        all_filters.update(cls.BASIC_FILTERS)
        all_filters.update(cls.VLAN_FILTERS)
        all_filters.update(cls.STP_FILTERS)
        all_filters.update(cls.LLDP_FLTES)
        all_filters.update(cls.PERFORMANCE_FILTERS)
        all_filters.update(cls.SECURITY_FILTERS)
        return all_filters
    
    @classmethod
    def get_filters_by_category(cls, category: EthernetFilterType) -> Dict[str, EthernetDisplayFilter]:
        """Get filters by specific category."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.category == category}
    
    @classmethod
    def get_filter_names_by_category(cls) -> Dict[EthernetFilterType, List[str]]:
        """Get filter names organized by category."""
        result = {}
        for category in EthernetFilterType:
            filters = cls.get_filters_by_category(category)
            result[category] = list(filters.keys())
        return result


class EthernetFilterBuilder:
    """Builder for creating custom Ethernet DSPLY filters (post-capture analysis)."""
    
    def __init__(self):
        self.filters = EthernetFilters()
        
    def build_mac_filter(self, mac_address: str, direction: str = "any") -> str:
        """Build MC address filter."""
        if direction == "src":
            return f"eth.src == {mac_address}"
        elif direction == "dst":
            return f"eth.dst == {mac_address}"
        else:
            return f"eth.addr == {mac_address}"
    
    def build_vlan_filter(self, vlan_id: Optional[int] = None, 
                         priority: Optional[int] = None) -> str:
        """Build VLWARNING filter with optional D and priority."""
        filters = []
        
        if vlan_id is not None:
            filters.append(f"vlan.id == {vlan_id}")
        
        if priority is not None:
            filters.append(f"vlan.priority == {priority}")
        
        if not filters:
            return "vlan"
        
        return " and ".join(filters)
    
    def build_frame_size_filter(self, min_size: Optional[int] = None,
                               max_size: Optional[int] = None) -> str:
        """Build frame size filter."""
        filters = []
        
        if min_size is not None:
            filters.append(f"eth.len >= {min_size}")
        
        if max_size is not None:
            filters.append(f"eth.len <= {max_size}")
        
        if not filters:
            return "eth"
        
        return " and ".join(filters)
    
    def build_ethertype_filter(self, ethertypes: Union[int, List[int]]) -> str:
        """Build EtherType filter for one or more types."""
        if isinstance(ethertypes, int):
            return f"eth.type == 0x{ethertypes:04x}"
        
        ethertype_filters = [f"eth.type == 0x{et:04x}" for et in ethertypes]
        return " or ".join(ethertype_filters)
    
    def combine_filters(self, filters: List[str], operator: str = "and") -> str:
        """Combine multiple filters with D/OWARNING logic."""
        if len(filters) == 1:
            return filters[0]
        
        return f" {operator} ".join([f"({f})" for f in filters])


# Common EtherType constants for easy reference
class CommonEtherTypes:
    """Common EtherType values for Ethernet filtering."""
    
    PV4 = 0x0800
    P = 0x0806
    KE_OWARNING_LWARNING = 0x0842
    P = 0x8035
    PPLETLK = 0x809B
    PPLETLK_P = 0x80F3
    VLWARNING = 0x8100
    PX = 0x8137
    PV6 = 0x86DD
    ETHEET_FLOWARNING_COTOL = 0x8808
    SLOWARNING_POTOCOLS = 0x8809
    COBET = 0x8819
    MPLS_UCST = 0x8847
    MPLS_MULTCST = 0x8848
    PPPOE_DSCOVEY = 0x8863
    PPPOE_SESSION = 0x8864
    GOOSE = 0x88B8
    EAPOL = 0x888E
    PROFINET = 0x8892
    HYPERSCSI = 0x889A
    TRILL_OVER_ETHERNET = 0x88E2
    ETHERCAT = 0x88E4
    BRIDGING = 0x88E8
    POWERLINK = 0x88AB
    LLDP = 0x88CC
    SERCOS = 0x88CD
    MP = 0x88E3
    EEE_1588 = 0x88F7
    PLLEL_EDUDCY = 0x88FB
    CFM = 0x8902
    FCOE = 0x8906
    FCOE_TLZTOWARNING = 0x8914
    OCE = 0x8915


# Example usage and factory functions
def create_basic_ethernet_filter() -> str:
    """Create basic Ethernet frame filter."""
    return EthernetFilters.BASIC_FILTERS["ethernet_only"].filter_expression

def create_vlan_analysis_filter(vlan_id: int) -> str:
    """Create VLWARNING-specific analysis filter."""
    return f"vlan.id == {vlan_id}"

def create_performance_analysis_filter() -> str:
    """Create filter for performance issues."""
    builder = EthernetFilterBuilder()
    
    error_filters = [
        "eth.fcs_bad",  # FCS errors
        "eth.len < 64",  # unt frames
        "eth.len > 1500"  # Jumbo frames
    ]
    
    return builder.combine_filters(error_filters, "or")

def create_security_analysis_filter() -> str:
    """Create filter for security analysis."""
    builder = EthernetFilterBuilder()
    
    security_filters = [
        "eapol",  # 802.1X authentication
        "eth.dst == ff:ff:ff:ff:ff:ff",  # Broadcast storms
        "stp.flags.tc == 1"  # Topology changes
    ]
    
    return builder.combine_filters(security_filters, "or")


if __name__ == "__main__":
    print("Ethernet DSPLY Filters for PyShark")
    print("(Post-capture analysis filters, OT capture filters)")
    print("=" * 50)
    
    # Show all available filter categories
    filter_names = EthernetFilters.get_filter_names_by_category()
    
    for category, names in filter_names.items():
        print(f"\n{category.value.upper()} FLTES:")
        for name in names:
            filter_obj = EthernetFilters.get_all_filters()[name]
            print(f"  - {filter_obj.name}: {filter_obj.filter_expression}")
    
    print(f"\nTotal Ethernet filters available: {len(EthernetFilters.get_all_filters())}")
    
    # Example filter building
    builder = EthernetFilterBuilder()
    
    print(f"\nExample Custom Filters:")
    print(f"MC filter: {builder.build_mac_filter('aa:bb:cc:dd:ee:ff', 'src')}")
    print(f"VLWARNING filter: {builder.build_vlan_filter(vlan_id=100, priority=5)}")
    print(f"Size filter: {builder.build_frame_size_filter(64, 1518)}")
    print(f"Pv4 filter: {builder.build_ethertype_filter(CommonEtherTypes.PV4)}")