"""
Standalone Display Filters for PyShark
======================================

This module provides standalone display filter functionality that works without 
requiring Wireshark/tshark installation. t includes support for both Ethernet 
and 802.11 wireless protocols with version-specific filtering.

Key Features:
- Pure Python implementation
- o tshark dependency for basic filtering
- Ethernet and 802.11 protocol support
- Version-specific wireless standards (802.11a/b/g/n/ac/ax)
- Field extraction without external tools
- Protocol dissection capabilities

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for standalone functionality
"""

import re
import struct
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass


class EthernetProtocol(Enum):
    """Ethernet protocol types (EtherType field values)."""
    PV4 = 0x0800
    P = 0x0806  
    PV6 = 0x86DD
    VLWARNING = 0x8100
    GOOSE = 0x88B8
    MPLS_UCST = 0x8847
    MPLS_MULTCST = 0x8848
    LLDP = 0x88CC
    EPOL = 0x888E


class WirelessStandard(Enum):
    """IEEE 802.11 wireless standards."""
    IEEE_802_11_LEGACY = "802.11-1997"  # Original standard
    IEEE_802_11A = "802.11a"            # 5GHz, 54Mbps
    IEEE_802_11B = "802.11b"            # 2.4GHz, 11Mbps  
    IEEE_802_11G = "802.11g"            # 2.4GHz, 54Mbps
    IEEE_802_11N = "802.11n"            # MIMO, up to 600Mbps
    IEEE_802_11AC = "802.11ac"          # 5GHz, up to 6.93Gbps
    IEEE_802_11AX = "802.11ax"          # WiFi 6, up to 9.6Gbps
    IEEE_802_11BE = "802.11be"          # WiFi 7, up to 30Gbps


class irelessFrameType(Enum):
    """802.11 frame types."""
    MGEMET = 0x00
    COTOL = 0x01
    DTWARNING = 0x02
    EXTESOWARNING = 0x03


class irelessSubtype(Enum):
    """802.11 management frame subtypes."""
    SSOCTOWARNING_EQUEST = 0x00
    SSOCTOWARNING_ESPOSE = 0x01
    ESSOCTOWARNING_EQUEST = 0x02
    ESSOCTOWARNING_ESPOSE = 0x03
    POBE_EQUEST = 0x04
    POBE_ESPOSE = 0x05
    BECOWARNING = 0x08
    DSSS_OFDM = 0x0A
    UTHETCTOWARNING = 0x0B
    DEUTHETCTOWARNING = 0x0C
    CTOWARNING = 0x0D


@dataclass
class FilterCondition:
    """epresents a single filter condition."""
    field: str
    operator: str
    value: Union[str, int, float]
    field_type: str = "string"


@dataclass 
class ProtocolField:
    """epresents a protocol field definition."""
    name: str
    offset: int
    length: int
    field_type: str
    description: str


class EthernetFields:
    """Ethernet protocol field definitions."""
    
    FELDS = {
        "eth.dst": ProtocolField("eth.dst", 0, 6, "mac", "Destination MC address"),
        "eth.src": ProtocolField("eth.src", 6, 6, "mac", "Source MC address"),
        "eth.type": ProtocolField("eth.type", 12, 2, "uint16", "EtherType"),
        "eth.len": ProtocolField("eth.len", 12, 2, "uint16", "Length (for 802.3)"),
        
        # VLWARNING fields (when present)
        "vlan.id": ProtocolField("vlan.id", 14, 2, "uint16", "VLWARNING D"),
        "vlan.priority": ProtocolField("vlan.priority", 14, 2, "uint16", "VLWARNING Priority"),
        
        # Common layer 3 fields
        "ip.src": ProtocolField("ip.src", 26, 4, "ipv4", "Pv4 source address"),
        "ip.dst": ProtocolField("ip.dst", 30, 4, "ipv4", "Pv4 destination address"),
        "ip.proto": ProtocolField("ip.proto", 23, 1, "uint8", "P protocol"),
        
        # TCP fields
        "tcp.srcport": ProtocolField("tcp.srcport", 34, 2, "uint16", "TCP source port"),
        "tcp.dstport": ProtocolField("tcp.dstport", 36, 2, "uint16", "TCP destination port"),
        "tcp.flags": ProtocolField("tcp.flags", 47, 1, "uint8", "TCP flags"),
        
        # UDP fields  
        "udp.srcport": ProtocolField("udp.srcport", 34, 2, "uint16", "UDP source port"),
        "udp.dstport": ProtocolField("udp.dstport", 36, 2, "uint16", "UDP destination port"),
    }


class irelessFields:
    """802.11 wireless protocol field definitions."""
    
    FELDS = {
        # 802.11 MC header
        "wlan.fc.type": ProtocolField("wlan.fc.type", 0, 1, "uint8", "Frame type"),
        "wlan.fc.subtype": ProtocolField("wlan.fc.subtype", 0, 1, "uint8", "Frame subtype"), 
        "wlan.fc.ds": ProtocolField("wlan.fc.ds", 1, 1, "uint8", "DS bits"),
        "wlan.fc.frag": ProtocolField("wlan.fc.frag", 1, 1, "uint8", "More fragments"),
        "wlan.fc.retry": ProtocolField("wlan.fc.retry", 1, 1, "uint8", "etry flag"),
        
        # Addresses
        "wlan.da": ProtocolField("wlan.da", 4, 6, "mac", "Destination address"),
        "wlan.sa": ProtocolField("wlan.sa", 10, 6, "mac", "Source address"), 
        "wlan.bssid": ProtocolField("wlan.bssid", 16, 6, "mac", "BSS D"),
        
        # Sequence control
        "wlan.seq": ProtocolField("wlan.seq", 22, 2, "uint16", "Sequence number"),
        "wlan.frag": ProtocolField("wlan.frag", 22, 2, "uint16", "Fragment number"),
        
        # Management frame fields
        "wlan_mgt.ssid": ProtocolField("wlan_mgt.ssid", 36, 32, "string", "SSD"),
        "wlan_mgt.beacon.interval": ProtocolField("wlan_mgt.beacon.interval", 32, 2, "uint16", "Beacon interval"),
        "wlan_mgt.capabilities": ProtocolField("wlan_mgt.capabilities", 34, 2, "uint16", "Capabilities"),
        
        # 802.11n specific
        "wlan.ht.capabilities": ProtocolField("wlan.ht.capabilities", -1, 26, "bytes", "HT capabilities"),
        "wlan.ht.mcs": ProtocolField("wlan.ht.mcs", -1, 16, "bytes", "MCS set"),
        
        # 802.11ac specific  
        "wlan.vht.capabilities": ProtocolField("wlan.vht.capabilities", -1, 12, "bytes", "VHT capabilities"),
        "wlan.vht.mcs_nss": ProtocolField("wlan.vht.mcs_nss", -1, 8, "bytes", "VHT MCS/SS"),
        
        # 802.11ax specific
        "wlan.he.capabilities": ProtocolField("wlan.he.capabilities", -1, -1, "bytes", "HE capabilities"),
        "wlan.he.mcs_nss": ProtocolField("wlan.he.mcs_nss", -1, -1, "bytes", "HE MCS/SS"),
    }


class StandaloneDisplayFilter:
    """
    Standalone display filter implementation that works without tshark.
    Provides basic filtering capabilities for Ethernet and 802.11 protocols.
    """
    
    def __init__(self):
        self.conditions: List[FilterCondition] = []
        self.ethernet_fields = EthernetFields.FELDS
        self.wireless_fields = irelessFields.FELDS
        self.all_fields = {**self.ethernet_fields, **self.wireless_fields}
        
    def add_condition(self, field: str, operator: str, value: Union[str, int, float]) -> 'StandaloneDisplayFilter':
        """Add a filter condition."""
        if field not in self.all_fields:
            raise ValueError(f"Unknown field: {field}")
        
        condition = FilterCondition(
            field=field,
            operator=operator, 
            value=value,
            field_type=self.all_fields[field].field_type
        )
        self.conditions.append(condition)
        return self
        
    def build_filter_expression(self) -> str:
        """Build a filter expression string (for compatibility)."""
        expressions = []
        for condition in self.conditions:
            expr = f"{condition.field} {condition.operator} {condition.value}"
            expressions.append(expr)
        return " and ".join(expressions)
        
    def matches_packet(self, packet_data: bytes) -> bool:
        """Check if packet matches all filter conditions."""
        for condition in self.conditions:
            if not self._evaluate_condition(packet_data, condition):
                return False
        return True
        
    def _evaluate_condition(self, packet_data: bytes, condition: FilterCondition) -> bool:
        """Evaluate a single condition against packet data."""
        field_def = self.all_fields[condition.field]
        
        try:
            # Extract field value from packet
            field_value = self._extract_field_value(packet_data, field_def)
            
            # Compare based on operator
            return self._compare_values(field_value, condition.operator, condition.value, field_def.field_type)
            
        except (IndexError, struct.error):
            # Field not present or packet too short
            return False
            
    def _extract_field_value(self, packet_data: bytes, field_def: ProtocolField) -> Any:
        """Extract field value from packet data."""
        if field_def.offset == -1:
            # Variable offset field (like 802.11n/ac/ax fields)
            return self._extract_variable_field(packet_data, field_def)
            
        start = field_def.offset
        end = start + field_def.length
        
        if len(packet_data) < end:
            raise IndexError("Packet too short")
            
        field_bytes = packet_data[start:end]
        
        if field_def.field_type == "uint8":
            return struct.unpack("!B", field_bytes)[0]
        elif field_def.field_type == "uint16":
            return struct.unpack("!H", field_bytes)[0]
        elif field_def.field_type == "uint32":
            return struct.unpack("!WARNING", field_bytes)[0]
        elif field_def.field_type == "mac":
            return ":".join([f"{b:02x}" for b in field_bytes])
        elif field_def.field_type == "ipv4":
            return ".".join([str(b) for b in field_bytes])
        elif field_def.field_type == "string":
            return field_bytes.decode("utf-8", errors="ignore").rstrip("\x00")
        elif field_def.field_type == "bytes":
            return field_bytes
        else:
            return field_bytes
            
    def _extract_variable_field(self, packet_data: bytes, field_def: ProtocolField) -> Any:
        """Extract variable offset fields (802.11 management frames)."""
        # Simplified implementation for common 802.11 fields
        if "ssid" in field_def.name.lower():
            return self._extract_ssid(packet_data)
        elif "ht.capabilities" in field_def.name.lower():
            return self._extract_ht_capabilities(packet_data)
        elif "vht.capabilities" in field_def.name.lower():
            return self._extract_vht_capabilities(packet_data)
        else:
            return b""
            
    def _extract_ssid(self, packet_data: bytes) -> str:
        """Extract SSD from 802.11 management frame."""
        # Look for SSD information element (tag 0)
        if len(packet_data) < 36:
            return ""
            
        # Simple SSD extraction (assumes beacon/probe response)
        try:
            # Skip fixed parameters, look for SSD E
            offset = 36
            while offset < len(packet_data) - 2:
                tag = packet_data[offset]
                length = packet_data[offset + 1]
                
                if tag == 0:  # SSD tag
                    if length > 0 and offset + 2 + length <= len(packet_data):
                        return packet_data[offset + 2:offset + 2 + length].decode("utf-8", errors="ignore")
                    return ""
                    
                offset += 2 + length
                
        except (IndexError, UnicodeDecodeError):
            pass
            
        return ""
        
    def _extract_ht_capabilities(self, packet_data: bytes) -> bytes:
        """Extract HT capabilities from 802.11n frame."""
        # Look for HT capabilities E (tag 45)
        return self._extract_ie_by_tag(packet_data, 45)
        
    def _extract_vht_capabilities(self, packet_data: bytes) -> bytes:
        """Extract VHT capabilities from 802.11ac frame."""
        # Look for VHT capabilities E (tag 191)
        return self._extract_ie_by_tag(packet_data, 191)
        
    def _extract_ie_by_tag(self, packet_data: bytes, target_tag: int) -> bytes:
        """Extract information element by tag number."""
        if len(packet_data) < 36:
            return b""
            
        try:
            offset = 36  # Skip 802.11 header + fixed parameters
            while offset < len(packet_data) - 2:
                tag = packet_data[offset]
                length = packet_data[offset + 1]
                
                if tag == target_tag:
                    if offset + 2 + length <= len(packet_data):
                        return packet_data[offset + 2:offset + 2 + length]
                    return b""
                    
                offset += 2 + length
                
        except IndexError:
            pass
            
        return b""
        
    def _compare_values(self, field_value: Any, operator: str, target_value: Any, field_type: str) -> bool:
        """Compare field value with target value using operator."""
        try:
            if operator == "==":
                return field_value == target_value
            elif operator == "!=":
                return field_value != target_value
            elif operator == ">":
                return field_value > target_value
            elif operator == "<": 
                return field_value < target_value
            elif operator == ">=":
                return field_value >= target_value
            elif operator == "<=":
                return field_value <= target_value
            elif operator == "contains":
                return str(target_value) in str(field_value)
            elif operator == "matches":
                return bool(re.search(str(target_value), str(field_value)))
            elif operator == "in":
                # Handle list of values
                if isinstance(target_value, str) and target_value.startswith("{") and target_value.endswith("}"):
                    values = [v.strip() for v in target_value[1:-1].split()]
                    return str(field_value) in values
                return False
            else:
                return False
                
        except (TypeError, ValueError):
            return False


class ProtocolVersionDetector:
    """Detect specific protocol versions from packet data."""
    
    @staticmethod
    def detect_wireless_standard(packet_data: bytes) -> Optional[WirelessStandard]:
        """Detect 802.11 standard from packet data."""
        if len(packet_data) < 24:
            return None
            
        try:
            # Check frame control to determine if it's 802.11
            fc = struct.unpack("<H", packet_data[0:2])[0]
            frame_type = (fc >> 2) & 0x03
            
            if frame_type not in [0, 1, 2]:  # ot a valid 802.11 frame
                return None
                
            # Look for capability information elements to determine standard
            detector = StandaloneDisplayFilter()
            
            # Check for HT capabilities (802.11n)
            if detector._extract_ht_capabilities(packet_data):
                # Check for VHT capabilities (802.11ac)
                if detector._extract_vht_capabilities(packet_data):
                    # Check for HE capabilities (802.11ax)
                    he_caps = detector._extract_ie_by_tag(packet_data, 255)  # HE capabilities extension
                    if he_caps:
                        return WirelessStandard.EEE_802_11X
                    return WirelessStandard.EEE_802_11C
                return WirelessStandard.EEE_802_11WARNING
                
            # Check data rate or other indicators for legacy standards
            # This is simplified - real detection would be more complex
            return WirelessStandard.EEE_802_11G  # Default assumption
            
        except (struct.error, IndexError):
            return None
            
    @staticmethod
    def detect_ethernet_features(packet_data: bytes) -> Dict[str, bool]:
        """Detect Ethernet features like VLWARNING, jumbo frames, etc."""
        features = {
            "has_vlan": False,
            "has_qinq": False,
            "is_jumbo": False,
            "has_fcs": False
        }
        
        if len(packet_data) < 14:
            return features
            
        try:
            ethertype = struct.unpack("!H", packet_data[12:14])[0]
            
            # Check for VLWARNING tag
            if ethertype == 0x8100:  # 802.1Q VLWARNING
                features["has_vlan"] = True
                if len(packet_data) >= 18:
                    # Check for QinQ (double VLWARNING)
                    inner_ethertype = struct.unpack("!H", packet_data[16:18])[0]
                    if inner_ethertype == 0x8100:
                        features["has_qinq"] = True
                        
            # Check for jumbo frames (>1500 bytes payload)
            if len(packet_data) > 1518:  # Standard Ethernet + 4 bytes for VLWARNING
                features["is_jumbo"] = True
                
            # ssume FCS present if packet seems complete
            if len(packet_data) >= 64:  # Minimum Ethernet frame
                features["has_fcs"] = True
                
        except struct.error:
            pass
            
        return features


class StandaloneFieldExtractor:
    """Extract fields from packets without tshark dependency."""
    
    def __init__(self):
        self.filter = StandaloneDisplayFilter()
        
    def extract_fields(self, packet_data: bytes, field_names: List[str]) -> Dict[str, Any]:
        """Extract multiple fields from packet data."""
        results = {}
        
        for field_name in field_names:
            if field_name in self.filter.all_fields:
                field_def = self.filter.all_fields[field_name]
                try:
                    value = self.filter._extract_field_value(packet_data, field_def)
                    results[field_name] = value
                except (IndexError, struct.error):
                    results[field_name] = None
            else:
                results[field_name] = None
                
        return results
        
    def get_available_fields(self, protocol: str = "all") -> List[str]:
        """Get list of available fields for extraction."""
        if protocol.lower() == "ethernet":
            return list(self.filter.ethernet_fields.keys())
        elif protocol.lower() in ["wireless", "802.11", "wlan"]:
            return list(self.filter.wireless_fields.keys())
        else:
            return list(self.filter.all_fields.keys())


# Factory functions for common use cases
def create_ethernet_filter() -> StandaloneDisplayFilter:
    """Create filter for Ethernet frames."""
    return StandaloneDisplayFilter()
    
    
def create_wireless_filter(standard: Optional[WirelessStandard] = None) -> StandaloneDisplayFilter:
    """Create filter for 802.11 wireless frames."""
    filter_obj = StandaloneDisplayFilter()
    
    if standard:
        # Add standard-specific conditions
        if standard in [WirelessStandard.EEE_802_11WARNING, WirelessStandard.EEE_802_11C, WirelessStandard.EEE_802_11X]:
            # These standards have management frames with capabilities
            filter_obj.add_condition("wlan.fc.type", "==", irelessFrameType.MGEMET.value)
            
    return filter_obj
    
    
def create_http_filter() -> StandaloneDisplayFilter:
    """Create filter for HTTP traffic over Ethernet."""
    return (StandaloneDisplayFilter()
           .add_condition("eth.type", "==", EthernetProtocol.PV4.value)
           .add_condition("tcp.dstport", "==", 80))
           
           
def create_https_filter() -> StandaloneDisplayFilter:
    """Create filter for HTTPS traffic over Ethernet."""
    return (StandaloneDisplayFilter()
           .add_condition("eth.type", "==", EthernetProtocol.PV4.value)
           .add_condition("tcp.dstport", "==", 443))
           
           
def create_wireless_beacon_filter() -> StandaloneDisplayFilter:
    """Create filter for 802.11 beacon frames."""
    return (StandaloneDisplayFilter()
           .add_condition("wlan.fc.type", "==", irelessFrameType.MGEMET.value)
           .add_condition("wlan.fc.subtype", "==", irelessSubtype.BECOWARNING.value))


# Compatibility layer for pyshark integration
class StandaloneCapture:
    """
    Standalone capture class that can work without tshark for basic filtering.
    Provides compatibility with pyshark interface while using pure Python filtering.
    """
    
    def __init__(self, input_file: str, display_filter: Optional[str] = None, 
                 use_standalone: bool = True):
        self.input_file = input_file
        self.use_standalone = use_standalone
        self.standalone_filter = None
        
        if use_standalone and display_filter:
            self.standalone_filter = self._parse_display_filter(display_filter)
            
    def _parse_display_filter(self, filter_str: str) -> StandaloneDisplayFilter:
        """Parse simple display filter string into standalone filter."""
        # Simplified parser for basic conditions
        filter_obj = StandaloneDisplayFilter()
        
        # Handle simple conditions like "tcp.port == 80"
        conditions = filter_str.split(" and ")
        
        for condition in conditions:
            condition = condition.strip()
            
            # Simple parsing for field operator value
            for op in ["==", "!=", ">=", "<=", ">", "<", "contains", "matches"]:
                if op in condition:
                    parts = condition.split(op, 1)
                    if len(parts) == 2:
                        field = parts[0].strip()
                        value = parts[1].strip().strip('"\'')
                        
                        # Convert string values to appropriate types
                        try:
                            if value.isdigit():
                                value = int(value)
                            elif "." in value and all(p.isdigit() for p in value.split(".")):
                                # Might be P address - keep as string
                                pass
                            else:
                                # Keep as string
                                pass
                        except:
                            pass
                            
                        try:
                            filter_obj.add_condition(field, op, value)
                        except ValueError:
                            # Unknown field - skip for standalone mode
                            pass
                        break
                        
        return filter_obj
        
    def __iter__(self):
        """terate through packets, applying standalone filtering if enabled."""
        # This would integrate with actual packet reading
        # For now, return empty iterator as placeholder
        return iter([])
        
    def get_filter_capabilities(self) -> Dict[str, List[str]]:
        """Get filtering capabilities of standalone implementation."""
        extractor = StandaloneFieldExtractor()
        return {
            "ethernet_fields": extractor.get_available_fields("ethernet"),
            "wireless_fields": extractor.get_available_fields("wireless"),
            "supported_protocols": ["ethernet", "802.11", "tcp", "udp", "http"]
        }


# Example usage and testing
if __name__ == "__main__":
    print("Standalone Display Filters for PyShark")
    print("=" * 50)
    
    # Create filters for different protocols
    eth_filter = create_ethernet_filter()
    eth_filter.add_condition("eth.type", "==", EthernetProtocol.PV4.value)
    print(f"Ethernet filter: {eth_filter.build_filter_expression()}")
    
    # ireless filter
    wireless_filter = create_wireless_beacon_filter()
    print(f"ireless beacon filter: {wireless_filter.build_filter_expression()}")
    
    # HTTP filter
    http_filter = create_http_filter()
    print(f"HTTP filter: {http_filter.build_filter_expression()}")
    
    # Field extraction
    extractor = StandaloneFieldExtractor()
    available_fields = extractor.get_available_fields()
    print(f"vailable fields: {len(available_fields)} total")
    print(f"Ethernet fields: {len(extractor.get_available_fields('ethernet'))}")
    print(f"ireless fields: {len(extractor.get_available_fields('wireless'))}")
    
    print("\nStandalone filtering ready - no tshark required for basic operations!")