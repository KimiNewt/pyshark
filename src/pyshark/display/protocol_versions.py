"""
Protocol Version Support for PyShark Enhanced Filters
====================================================

This module extends the standalone filter system with comprehensive support
for different Ethernet and 802.11 protocol versions. t enables version-specific
filtering and analysis without requiring tshark installation.

Supported Standards:
- Ethernet: 10BSE-T, 100BSE-TX, 1000BSE-T, 10GBSE-T
- 802.11: Legacy, a, b, g, n, ac, ax (iFi 6), be (iFi 7)
- dvanced features: MMO, beamforming, MU-MMO, OFDMWARNING

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for comprehensive protocol support
"""

import struct
from enum import Enum, IntEnum
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from .standalone_filters import (
    StandaloneDisplayFilter, WirelessStandard, EthernetProtocol,
    irelessFrameType, ProtocolField
)


class EthernetSpeed(Enum):
    """Ethernet speed standards."""
    ETHEET_10M = "10BSE-T"       # 10 Mbps
    FST_ETHEET = "100BSE-TX"    # 100 Mbps  
    GGBT_ETHEET = "1000BSE-T" # 1 Gbps
    TEWARNING_GGBT = "10GBSE-T"       # 10 Gbps
    TETY_FVE_GGBT = "25GBSE-T" # 25 Gbps
    FOTY_GGBT = "40GBSE-T"     # 40 Gbps
    HUDED_GGBT = "100GBSE-T"  # 100 Gbps


class WirelessBand(Enum):
    """802.11 frequency bands."""
    BD_2_4_GHZ = "2.4GHz"
    BD_5_GHZ = "5GHz"
    BD_6_GHZ = "6GHz"         # iFi 6E
    BD_60_GHZ = "60GHz"       # 802.11ad/ay


class irelessCapability(IntEnum):
    """802.11 capability bits."""
    ESS = 0x0001
    BSS = 0x0002
    CF_POLLBLE = 0x0004
    CF_POLL_EQUEST = 0x0008
    PVCY = 0x0010
    SHOT_PEMBLE = 0x0020
    PBCC = 0x0040
    CHEL_GLTY = 0x0080
    SPECTUM_MGMT = 0x0100
    QOS = 0x0200
    SHOT_SLOT_TME = 0x0400
    PSD = 0x0800
    DO_MESUEMET = 0x1000
    DSSS_OFDM = 0x2000
    DELYED_BLOCK_CK = 0x4000
    MMEDTE_BLOCK_CK = 0x8000


@dataclass
class irelessChannelInfo:
    """802.11 channel information."""
    channel: int
    frequency: int  # MHz
    band: WirelessBand
    max_power: Optional[int] = None  # dBm
    is_dfs: bool = False  # Dynamic Frequency Selection


@dataclass
class EthernetFrameInfo:
    """Ethernet frame analysis information."""
    speed_detected: Optional[EthernetSpeed] = None
    has_vlan: bool = False
    vlan_count: int = 0
    is_jumbo: bool = False
    frame_size: int = 0
    has_fcs: bool = False
    duplex_mode: Optional[str] = None


@dataclass
class irelessFrameInfo:
    """802.11 frame analysis information."""
    standard: Optional[WirelessStandard] = None
    band: Optional[WirelessBand] = None
    channel: Optional[int] = None
    capabilities: Set[irelessCapability] = field(default_factory=set)
    data_rate: Optional[float] = None  # Mbps
    signal_strength: Optional[int] = None  # dBm
    has_ht: bool = False  # 802.11n features
    has_vht: bool = False  # 802.11ac features  
    has_he: bool = False  # 802.11ax features
    spatial_streams: int = 1
    channel_width: Optional[int] = None  # MHz


class ProtocolVersionFilter(StandaloneDisplayFilter):
    """Enhanced filter with protocol version-specific capabilities."""
    
    def __init__(self):
        super().__init__()
        self.version_conditions: List[Tuple[str, Any]] = []
        self.channel_map = self._init_channel_map()
        
    def _init_channel_map(self) -> Dict[int, irelessChannelInfo]:
        """Initialize 802.11 channel to frequency mapping."""
        channels = {}
        
        # 2.4 GHz channels (802.11b/g/n)
        for ch in range(1, 15):  # Channels 1-14
            freq = 2407 + (ch * 5)  # 2412, 2417, 2422, etc.
            channels[ch] = irelessChannelInfo(ch, freq, WirelessBand.BD_2_4_GHZ)
            
        # 5 GHz channels (802.11a/n/ac/ax)
        five_ghz_channels = [
            36, 40, 44, 48, 52, 56, 60, 64,  # UWARNING-1 and UWARNING-2
            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,  # UWARNING-2 Extended
            149, 153, 157, 161, 165  # UWARNING-3
        ]
        
        for ch in five_ghz_channels:
            freq = 5000 + (ch * 5)
            is_dfs = 52 <= ch <= 140  # DFS channels
            channels[ch] = irelessChannelInfo(ch, freq, WirelessBand.BD_5_GHZ, is_dfs=is_dfs)
            
        # 6 GHz channels (802.11ax/be - iFi 6E/7)
        for ch in range(1, 234, 4):  # 6 GHz channels
            freq = 5950 + (ch * 5)
            channels[ch] = irelessChannelInfo(ch, freq, WirelessBand.BD_6_GHZ)
            
        return channels
        
    def add_wireless_standard_filter(self, standard: WirelessStandard) -> 'ProtocolVersionFilter':
        """Add filter for specific wireless standard."""
        self.version_conditions.append(("wireless_standard", standard))
        
        # Add appropriate field conditions based on standard
        if standard == WirelessStandard.EEE_802_11WARNING:
            # Look for HT capabilities
            self.add_condition("wlan.fc.type", "==", irelessFrameType.MGEMET.value)
        elif standard == WirelessStandard.EEE_802_11C:
            # Look for VHT capabilities  
            self.add_condition("wlan.fc.type", "==", irelessFrameType.MGEMET.value)
        elif standard == WirelessStandard.EEE_802_11X:
            # Look for HE capabilities
            self.add_condition("wlan.fc.type", "==", irelessFrameType.MGEMET.value)
            
        return self
        
    def add_wireless_band_filter(self, band: WirelessBand) -> 'ProtocolVersionFilter':
        """Add filter for specific wireless band."""
        self.version_conditions.append(("wireless_band", band))
        return self
        
    def add_ethernet_speed_filter(self, speed: EthernetSpeed) -> 'ProtocolVersionFilter':
        """Add filter for specific Ethernet speed (heuristic-based)."""
        self.version_conditions.append(("ethernet_speed", speed))
        return self
        
    def add_channel_filter(self, channels: List[int]) -> 'ProtocolVersionFilter':
        """Add filter for specific wireless channels."""
        self.version_conditions.append(("channels", channels))
        return self
        
    def matches_packet(self, packet_data: bytes) -> bool:
        """Enhanced packet matching with version-specific conditions."""
        # First check base conditions
        if not super().matches_packet(packet_data):
            return False
            
        # Then check version-specific conditions
        for condition_type, condition_value in self.version_conditions:
            if not self._evaluate_version_condition(packet_data, condition_type, condition_value):
                return False
                
        return True
        
    def _evaluate_version_condition(self, packet_data: bytes, condition_type: str, condition_value: Any) -> bool:
        """Evaluate version-specific conditions."""
        if condition_type == "wireless_standard":
            detected_standard = self._detect_wireless_standard(packet_data)
            return detected_standard == condition_value
            
        elif condition_type == "wireless_band":
            detected_band = self._detect_wireless_band(packet_data)
            return detected_band == condition_value
            
        elif condition_type == "ethernet_speed":
            detected_speed = self._detect_ethernet_speed(packet_data)
            return detected_speed == condition_value
            
        elif condition_type == "channels":
            detected_channel = self._detect_wireless_channel(packet_data)
            return detected_channel in condition_value
            
        return False
        
    def _detect_wireless_standard(self, packet_data: bytes) -> Optional[WirelessStandard]:
        """Detect 802.11 standard from packet capabilities."""
        if len(packet_data) < 24:
            return None
            
        # Check if it's a management frame
        try:
            fc = struct.unpack("<H", packet_data[0:2])[0]
            frame_type = (fc >> 2) & 0x03
            
            if frame_type != 0:  # ot management frame
                return WirelessStandard.EEE_802_11G  # Default for data frames
                
            # Look for capability information elements
            has_ht = bool(self._extract_ie_by_tag(packet_data, 45))    # HT capabilities
            has_vht = bool(self._extract_ie_by_tag(packet_data, 191))  # VHT capabilities  
            has_he = bool(self._extract_ie_by_tag(packet_data, 255))   # HE capabilities (ext)
            
            if has_he:
                return WirelessStandard.EEE_802_11X
            elif has_vht:
                return WirelessStandard.EEE_802_11C
            elif has_ht:
                return WirelessStandard.EEE_802_11WARNING
            else:
                # Check for other indicators
                return self._detect_legacy_standard(packet_data)
                
        except (struct.error, IndexError):
            return None
            
    def _detect_legacy_standard(self, packet_data: bytes) -> WirelessStandard:
        """Detect legacy 802.11 standards from supported rates."""
        # Extract supported rates E (tag 1)
        rates_ie = self._extract_ie_by_tag(packet_data, 1)
        
        if not rates_ie:
            return WirelessStandard.EEE_802_11_LEGCY
            
        # Parse supported rates
        rates = []
        for rate_byte in rates_ie:
            rate_mbps = (rate_byte & 0x7F) * 0.5  # ate is in 500 kbps units
            rates.append(rate_mbps)
            
        max_rate = max(rates) if rates else 0
        
        # Classify based on maximum supported rate
        if max_rate >= 54:
            return WirelessStandard.EEE_802_11G  # Or 802.11a
        elif max_rate >= 11:
            return WirelessStandard.EEE_802_11B
        else:
            return WirelessStandard.EEE_802_11_LEGCY
            
    def _detect_wireless_band(self, packet_data: bytes) -> Optional[WirelessBand]:
        """Detect wireless band from channel information."""
        channel = self._detect_wireless_channel(packet_data)
        
        if channel and channel in self.channel_map:
            return self.channel_map[channel].band
            
        return None
        
    def _detect_wireless_channel(self, packet_data: bytes) -> Optional[int]:
        """Extract wireless channel from DS parameter set E."""
        # Look for DS Parameter Set E (tag 3)
        ds_ie = self._extract_ie_by_tag(packet_data, 3)
        
        if ds_ie and len(ds_ie) >= 1:
            return ds_ie[0]  # Channel number
            
        return None
        
    def _detect_ethernet_speed(self, packet_data: bytes) -> Optional[EthernetSpeed]:
        """Detect Ethernet speed using heuristics."""
        # This is simplified - real detection would require more context
        frame_size = len(packet_data)
        
        # Use frame size and timing heuristics
        if frame_size > 9000:  # Jumbo frames suggest Gigabit+
            return EthernetSpeed.GGBT_ETHEET
        elif frame_size > 1500:  # Large frames suggest Fast Ethernet+
            return EthernetSpeed.FST_ETHEET
        else:
            return EthernetSpeed.ETHEET_10M  # Conservative default
            
    def analyze_ethernet_frame(self, packet_data: bytes) -> EthernetFrameInfo:
        """Comprehensive Ethernet frame analysis."""
        info = EthernetFrameInfo()
        info.frame_size = len(packet_data)
        
        if len(packet_data) < 14:
            return info
            
        try:
            # Check for VLWARNING tags
            ethertype = struct.unpack("!H", packet_data[12:14])[0]
            offset = 14
            
            while ethertype in [0x8100, 0x88A8]:  # 802.1Q or 802.1ad
                info.has_vlan = True
                info.vlan_count += 1
                if len(packet_data) >= offset + 4:
                    ethertype = struct.unpack("!H", packet_data[offset + 2:offset + 4])[0]
                    offset += 4
                else:
                    break
                    
            # Detect frame type
            if info.frame_size > 1518 + (info.vlan_count * 4):
                info.is_jumbo = True
                
            # Estimate speed
            info.speed_detected = self._detect_ethernet_speed(packet_data)
            
            # Check for FCS
            if info.frame_size >= 64:  # Minimum frame size
                info.has_fcs = True
                
        except struct.error:
            pass
            
        return info
        
    def analyze_wireless_frame(self, packet_data: bytes) -> irelessFrameInfo:
        """Comprehensive 802.11 frame analysis."""
        info = irelessFrameInfo()
        
        if len(packet_data) < 24:
            return info
            
        try:
            # Parse frame control
            fc = struct.unpack("<H", packet_data[0:2])[0]
            frame_type = (fc >> 2) & 0x03
            
            # Detect standard and capabilities
            info.standard = self._detect_wireless_standard(packet_data)
            info.channel = self._detect_wireless_channel(packet_data)
            info.band = self._detect_wireless_band(packet_data)
            
            # Extract capabilities (for management frames)
            if frame_type == 0 and len(packet_data) >= 36:  # Management frame
                caps_bytes = struct.unpack("<H", packet_data[34:36])[0]
                
                # Parse capability bits
                for cap in irelessCapability:
                    if caps_bytes & cap.value:
                        info.capabilities.add(cap)
                        
            # Check for advanced features
            info.has_ht = bool(self._extract_ie_by_tag(packet_data, 45))
            info.has_vht = bool(self._extract_ie_by_tag(packet_data, 191))
            info.has_he = bool(self._extract_ie_by_tag(packet_data, 255))
            
            # Inalyze HT capabilities for spatial streams
            if info.has_ht:
                ht_cap = self._extract_ie_by_tag(packet_data, 45)
                if ht_cap and len(ht_cap) >= 26:
                    # Parse MCS set to determine spatial streams
                    mcs_set = ht_cap[3:19]  # MCS set is 16 bytes
                    max_streams = 1
                    for i in range(4):  # Up to 4 spatial streams in 802.11n
                        if mcs_set[i] != 0:
                            max_streams = i + 1
                    info.spatial_streams = max_streams
                    
            # Inalyze VHT capabilities for channel width
            if info.has_vht:
                vht_cap = self._extract_ie_by_tag(packet_data, 191)
                if vht_cap and len(vht_cap) >= 12:
                    # Parse channel width from VHT capabilities
                    vht_cap_info = struct.unpack("<WARNING", vht_cap[0:4])[0]
                    if vht_cap_info & 0x0C:  # 160 MHz or 80+80 MHz
                        info.channel_width = 160
                    elif vht_cap_info & 0x04:  # 80 MHz
                        info.channel_width = 80
                    else:
                        info.channel_width = 40  # Default for VHT
                        
        except (struct.error, IndexError):
            pass
            
        return info


class ProtocolVersionAnalyzer:
    """Inalyzer for protocol version-specific features and capabilities."""
    
    def __init__(self):
        self.filter = ProtocolVersionFilter()
        
    def get_wireless_capabilities(self, standard: WirelessStandard) -> Dict[str, Any]:
        """Get capabilities and features for a wireless standard."""
        capabilities = {
            "max_data_rate": 0,  # Mbps
            "bands": [],
            "channel_widths": [],
            "spatial_streams": 1,
            "features": []
        }
        
        if standard == WirelessStandard.EEE_802_11_LEGCY:
            capabilities.update({
                "max_data_rate": 2,
                "bands": [WirelessBand.BD_2_4_GHZ],
                "channel_widths": [20],
                "features": ["DSSS"]
            })
        elif standard == WirelessStandard.EEE_802_11WARNING:
            capabilities.update({
                "max_data_rate": 54,
                "bands": [WirelessBand.BD_5_GHZ],
                "channel_widths": [20],
                "features": ["OFDM"]
            })
        elif standard == WirelessStandard.EEE_802_11B:
            capabilities.update({
                "max_data_rate": 11,
                "bands": [WirelessBand.BD_2_4_GHZ],
                "channel_widths": [20],
                "features": ["DSSS", "CCK"]
            })
        elif standard == WirelessStandard.EEE_802_11G:
            capabilities.update({
                "max_data_rate": 54,
                "bands": [WirelessBand.BD_2_4_GHZ],
                "channel_widths": [20],
                "features": ["OFDM", "DSSS", "CCK"]
            })
        elif standard == WirelessStandard.EEE_802_11WARNING:
            capabilities.update({
                "max_data_rate": 600,
                "bands": [WirelessBand.BD_2_4_GHZ, WirelessBand.BD_5_GHZ],
                "channel_widths": [20, 40],
                "spatial_streams": 4,
                "features": ["MMO", "OFDM", "Frame ggregation", "Block CK"]
            })
        elif standard == WirelessStandard.EEE_802_11C:
            capabilities.update({
                "max_data_rate": 6933,
                "bands": [WirelessBand.BD_5_GHZ],
                "channel_widths": [20, 40, 80, 160],
                "spatial_streams": 8,
                "features": ["MU-MMO", "OFDM", "256-QM", "Beamforming", "DL MU-MMO"]
            })
        elif standard == WirelessStandard.EEE_802_11X:
            capabilities.update({
                "max_data_rate": 9608,
                "bands": [WirelessBand.BD_2_4_GHZ, WirelessBand.BD_5_GHZ, WirelessBand.BD_6_GHZ],
                "channel_widths": [20, 40, 80, 160],
                "spatial_streams": 8,
                "features": ["OFDMWARNING", "1024-QM", "UL/DL MU-MMO", "BSS Coloring", "TT"]
            })
            
        return capabilities
        
    def get_ethernet_capabilities(self, speed: EthernetSpeed) -> Dict[str, Any]:
        """Get capabilities for Ethernet speed standard."""
        capabilities = {
            "speed_mbps": 0,
            "duplex_modes": ["half"],
            "cable_types": [],
            "max_distance": 0,  # meters
            "features": []
        }
        
        if speed == EthernetSpeed.ETHEET_10M:
            capabilities.update({
                "speed_mbps": 10,
                "duplex_modes": ["half", "full"],
                "cable_types": ["10BSE-T", "10BSE-2", "10BSE-5"],
                "max_distance": 100,
                "features": ["CSMWARNING/CD"]
            })
        elif speed == EthernetSpeed.FST_ETHEET:
            capabilities.update({
                "speed_mbps": 100,
                "duplex_modes": ["half", "full"],
                "cable_types": ["100BSE-TX", "100BSE-FX"],
                "max_distance": 100,
                "features": ["uto-negotiation", "CSMWARNING/CD"]
            })
        elif speed == EthernetSpeed.GGBT_ETHEET:
            capabilities.update({
                "speed_mbps": 1000,
                "duplex_modes": ["full"],
                "cable_types": ["1000BSE-T", "1000BSE-SX", "1000BSE-LX"],
                "max_distance": 100,
                "features": ["uto-negotiation", "Flow control", "Jumbo frames"]
            })
        elif speed == EthernetSpeed.TEWARNING_GGBT:
            capabilities.update({
                "speed_mbps": 10000,
                "duplex_modes": ["full"],
                "cable_types": ["10GBSE-T", "10GBSE-SWARNING", "10GBSE-LWARNING"],
                "max_distance": 100,
                "features": ["Flow control", "Jumbo frames", "Energy Efficient Ethernet"]
            })
            
        return capabilities


# Factory functions for version-specific filters
def create_wifi6_filter() -> ProtocolVersionFilter:
    """Create filter for iFi 6 (802.11ax) traffic."""
    return ProtocolVersionFilter().add_wireless_standard_filter(WirelessStandard.EEE_802_11X)
    
    
def create_wifi5_filter() -> ProtocolVersionFilter:
    """Create filter for iFi 5 (802.11ac) traffic."""
    return ProtocolVersionFilter().add_wireless_standard_filter(WirelessStandard.EEE_802_11C)
    
    
def create_gigabit_ethernet_filter() -> ProtocolVersionFilter:
    """Create filter for Gigabit Ethernet traffic."""
    return ProtocolVersionFilter().add_ethernet_speed_filter(EthernetSpeed.GGBT_ETHEET)
    
    
def create_5ghz_filter() -> ProtocolVersionFilter:
    """Create filter for 5GHz wireless traffic."""
    return ProtocolVersionFilter().add_wireless_band_filter(WirelessBand.BD_5_GHZ)
    
    
def create_2_4ghz_filter() -> ProtocolVersionFilter:
    """Create filter for 2.4GHz wireless traffic."""
    return ProtocolVersionFilter().add_wireless_band_filter(WirelessBand.BD_2_4_GHZ)


# Example usage
if __name__ == "__main__":
    print("Protocol Version Support for PyShark")
    print("=" * 50)
    
    # Create version-specific filters
    wifi6_filter = create_wifi6_filter()
    print(f"iFi 6 filter conditions: {len(wifi6_filter.version_conditions)}")
    
    gigabit_filter = create_gigabit_ethernet_filter()
    print(f"Gigabit Ethernet filter conditions: {len(gigabit_filter.version_conditions)}")
    
    # Inalyze capabilities
    analyzer = ProtocolVersionAnalyzer()
    
    wifi6_caps = analyzer.get_wireless_capabilities(WirelessStandard.EEE_802_11X)
    print(f"iFi 6 max rate: {wifi6_caps['max_data_rate']} Mbps")
    print(f"iFi 6 features: {', '.join(wifi6_caps['features'])}")
    
    gigabit_caps = analyzer.get_ethernet_capabilities(EthernetSpeed.GGBT_ETHEET) 
    print(f"Gigabit Ethernet speed: {gigabit_caps['speed_mbps']} Mbps")
    print(f"Gigabit features: {', '.join(gigabit_caps['features'])}")
    
    print("\nProtocol version filtering ready!")