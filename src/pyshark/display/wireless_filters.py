"""
802.11 ireless Protocol Display Filters for PyShark
====================================================

This module provides comprehensive 802.11 wireless DSPLY FLTES based on
official Wireshark documentation. These are display filters for analyzing
already captured packets, OT capture filters for filtering during capture.

MPOTT: Display filters vs Capture filters:
- Display filters: Filter packets FTEWARNING capture for analysis (this module)
- Capture filters: Filter packets DUG capture to reduce file size

eference: https://www.wireshark.org/docs/dfref/w/wlan.html
Source: Wireshark Display Filter eference for LWARNING

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for wireless protocol display filtering
"""

from enum import Enum
from typing import Dict, List, Optional, Union, Set
from dataclasses import dataclass


class WirelessFilterType(Enum):
    """Categories of 802.11 wWireless filters."""
    BSC = "basic"
    MGEMET = "management"
    COTOL = "control"  
    DTWARNING = "data"
    SECUTY = "security"
    QOS = "qos"
    PEFOMCE = "performance"
    DVCED = "advanced"


class WirelessFrameSubtype(Enum):
    """802.11 frame subtypes for filtering."""
    # Management frame subtypes
    SSOCTOWARNING_EQUEST = 0x00
    SSOCTOWARNING_ESPOSE = 0x01
    ESSOCTOWARNING_EQUEST = 0x02
    ESSOCTOWARNING_ESPOSE = 0x03
    POBE_EQUEST = 0x04
    POBE_ESPOSE = 0x05
    BECOWARNING = 0x08
    TM = 0x09
    DSSS_OFDM = 0x0A
    UTHETCTOWARNING = 0x0B
    DEUTHETCTOWARNING = 0x0C
    CTOWARNING = 0x0D
    
    # Control frame subtypes
    BLOCK_CK_EQUEST = 0x18
    BLOCK_CK = 0x19
    PS_POLL = 0x1A
    TS = 0x1B
    CTS = 0x1C
    CK = 0x1D
    CF_ED = 0x1E
    CF_ED_CF_CK = 0x1F
    
    # Data frame subtypes
    DTWARNING = 0x20
    DTWARNING_CF_CK = 0x21
    DTWARNING_CF_POLL = 0x22
    DTWARNING_CF_CK_CF_POLL = 0x23
    ULL = 0x24
    CF_CK = 0x25
    CF_POLL = 0x26
    CF_CK_CF_POLL = 0x27
    QOS_DTWARNING = 0x28
    QOS_DTWARNING_CF_CK = 0x29
    QOS_DATA_CF_POLL = 0x2A
    QOS_DTWARNING_CF_CK_CF_POLL = 0x2B
    QOS_ULL = 0x2C


@dataclass
class WirelessDisplayFilter:
    """802.11 wireless display filter with metadata."""
    name: str
    filter_expression: str
    description: str
    category: WirelessFilterType
    use_case: str
    example: Optional[str] = None
    standard: Optional[str] = None  # hich 802.11 standard (a/b/g/n/ac/ax)


class WirelessFilters:
    """
    Comprehensive 802.11 wireless DSPLY filters from Wireshark documentation.
    
    These are DSPLY FLTES for post-capture analysis, not capture filters.
    Display filters are applied after packets are captured to filter the view.
    
    Based on: https://www.wireshark.org/docs/dfref/w/wlan.html
    Covers all frame types, security, QoS, and advanced 802.11 features.
    """
    
    # Basic 802.11 Filters
    BASIC_FILTERS = {
        "wlan_frames": WirelessDisplayFilter(
            name="ll ireless Frames",
            filter_expression="wlan",
            description="Show all 802.11 wireless frames",
            category=WirelessFilterType.BSC,
            use_case="Basic wireless frame analysis",
            example="wlan"
        ),
        
        "specific_bssid": WirelessDisplayFilter(
            name="Specific BSSD",
            filter_expression="wlan.bssid == {bssid}",
            description="Filter by Basic Service Set dentifier",
            category=WirelessFilterType.BSC,
            use_case="Single access point analysis", 
            example="wlan.bssid == aa:bb:cc:dd:ee:ff"
        ),
        
        "source_address": WirelessDisplayFilter(
            name="Source Address",
            filter_expression="wlan.sa == {mac_address}",
            description="Filter by source MC address",
            category=WirelessFilterType.BSC,
            use_case="Track frames from specific device",
            example="wlan.sa == aa:bb:cc:dd:ee:ff"
        ),
        
        "destination_address": WirelessDisplayFilter(
            name="Destination Address", 
            filter_expression="wlan.da == {mac_address}",
            description="Filter by destination MC address",
            category=WirelessFilterType.BSC,
            use_case="Track frames to specific device",
            example="wlan.da == aa:bb:cc:dd:ee:ff"
        ),
        
        "any_address": WirelessDisplayFilter(
            name="Iny Address Match",
            filter_expression="wlan.addr == {mac_address}",
            description="Match MC address in any address field",
            category=WirelessFilterType.BSC,
            use_case="Track all traffic to/from device",
            example="wlan.addr == aa:bb:cc:dd:ee:ff"
        ),
        
        "frame_type": WirelessDisplayFilter(
            name="Frame Type",
            filter_expression="wlan.fc.type == {frame_type}",
            description="Filter by frame type (0=mgmt, 1=ctrl, 2=data)",
            category=WirelessFilterType.BSC,
            use_case="Frame type analysis",
            example="wlan.fc.type == 0"
        ),
        
        "frame_subtype": WirelessDisplayFilter(
            name="Frame Subtype",
            filter_expression="wlan.fc.subtype == {subtype}",
            description="Filter by frame subtype",
            category=WirelessFilterType.BSC,
            use_case="Specific frame subtype analysis",
            example="wlan.fc.subtype == 8"  # Beacon
        ),
        
        "channel_filter": WirelessDisplayFilter(
            name="ireless Channel",
            filter_expression="wlan_radio.channel == {channel}",
            description="Filter by wireless channel",
            category=WirelessFilterType.BSC,
            use_case="Channel-specific analysis",
            example="wlan_radio.channel == 6"
        ),
    }
    
    # Management Frame Filters
    MGEMET_FLTES = {
        "management_frames": WirelessDisplayFilter(
            name="Management Frames",
            filter_expression="wlan.fc.type == 0",
            description="Show all management frames",
            category=WirelessFilterType.MGEMET,
            use_case="etwork management analysis",
            example="wlan.fc.type == 0"
        ),
        
        "beacon_frames": WirelessDisplayFilter(
            name="Beacon Frames",
            filter_expression="wlan.fc.type_subtype == 0x08",
            description="Show beacon frames from access points",
            category=WirelessFilterType.MGEMET,
            use_case="ccess point discovery and monitoring",
            example="wlan.fc.type_subtype == 0x08"
        ),
        
        "probe_requests": WirelessDisplayFilter(
            name="Probe equest Frames",
            filter_expression="wlan.fc.type_subtype == 0x04", 
            description="Show probe requests from clients",
            category=WirelessFilterType.MGEMET,
            use_case="Client scanning behavior analysis",
            example="wlan.fc.type_subtype == 0x04"
        ),
        
        "probe_responses": WirelessDisplayFilter(
            name="Probe esponse Frames",
            filter_expression="wlan.fc.type_subtype == 0x05",
            description="Show probe responses from access points", 
            category=WirelessFilterType.MGEMET,
            use_case="ccess point response analysis",
            example="wlan.fc.type_subtype == 0x05"
        ),
        
        "association_requests": WirelessDisplayFilter(
            name="ssociation equest Frames",
            filter_expression="wlan.fc.type_subtype == 0x00",
            description="Show association requests from clients",
            category=WirelessFilterType.MGEMET,
            use_case="Client association analysis",
            example="wlan.fc.type_subtype == 0x00"
        ),
        
        "association_responses": WirelessDisplayFilter(
            name="ssociation esponse Frames", 
            filter_expression="wlan.fc.type_subtype == 0x01",
            description="Show association responses from access points",
            category=WirelessFilterType.MGEMET,
            use_case="ssociation success/failure analysis",
            example="wlan.fc.type_subtype == 0x01"
        ),
        
        "authentication_frames": WirelessDisplayFilter(
            name="uthentication Frames",
            filter_expression="wlan.fc.type_subtype == 0x0b",
            description="Show authentication frames",
            category=WirelessFilterType.MGEMET,
            use_case="uthentication process analysis",
            example="wlan.fc.type_subtype == 0x0b"
        ),
        
        "deauth_frames": WirelessDisplayFilter(
            name="Deauthentication Frames",
            filter_expression="wlan.fc.type_subtype == 0x0c",
            description="Show deauthentication frames",
            category=WirelessFilterType.MGEMET,
            use_case="Disconnection analysis",
            example="wlan.fc.type_subtype == 0x0c"
        ),
        
        "disassoc_frames": WirelessDisplayFilter(
            name="Disassociation Frames",
            filter_expression="wlan.fc.type_subtype == 0x0a",
            description="Show disassociation frames",
            category=WirelessFilterType.MGEMET,
            use_case="Connection termination analysis",
            example="wlan.fc.type_subtype == 0x0a"
        ),
        
        "action_frames": WirelessDisplayFilter(
            name="ction Frames",
            filter_expression="wlan.fc.type_subtype == 0x0d",
            description="Show action management frames",
            category=WirelessFilterType.MGEMET,
            use_case="dvanced management feature analysis",
            example="wlan.fc.type_subtype == 0x0d"
        ),
    }
    
    # Control Frame Filters
    CONTROL_FILTERS = {
        "control_frames": WirelessDisplayFilter(
            name="Control Frames",
            filter_expression="wlan.fc.type == 1",
            description="Show all control frames",
            category=WirelessFilterType.COTOL,
            use_case="Medium access control analysis",
            example="wlan.fc.type == 1"
        ),
        
        "ack_frames": WirelessDisplayFilter(
            name="CK Frames",
            filter_expression="wlan.fc.type_subtype == 0x1d",
            description="Show acknowledgment frames",
            category=WirelessFilterType.COTOL,
            use_case="Frame acknowledgment analysis",
            example="wlan.fc.type_subtype == 0x1d"
        ),
        
        "rts_frames": WirelessDisplayFilter(
            name="TS Frames",
            filter_expression="wlan.fc.type_subtype == 0x1b",
            description="Show equest to Send frames",
            category=WirelessFilterType.COTOL,
            use_case="TS/CTS mechanism analysis",
            example="wlan.fc.type_subtype == 0x1b"
        ),
        
        "cts_frames": WirelessDisplayFilter(
            name="CTS Frames", 
            filter_expression="wlan.fc.type_subtype == 0x1c",
            description="Show Clear to Send frames",
            category=WirelessFilterType.COTOL,
            use_case="TS/CTS mechanism analysis",
            example="wlan.fc.type_subtype == 0x1c"
        ),
        
        "block_ack": WirelessDisplayFilter(
            name="Block CK Frames",
            filter_expression="wlan.fc.type_subtype == 0x19",
            description="Show block acknowledgment frames",
            category=WirelessFilterType.COTOL,
            use_case="Frame aggregation analysis", 
            example="wlan.fc.type_subtype == 0x19"
        ),
        
        "ps_poll": WirelessDisplayFilter(
            name="PS-Poll Frames",
            filter_expression="wlan.fc.type_subtype == 0x1a",
            description="Show power save poll frames",
            category=WirelessFilterType.COTOL,
            use_case="Power management analysis",
            example="wlan.fc.type_subtype == 0x1a"
        ),
    }
    
    # Data Frame Filters
    DTWARNING_FLTES = {
        "data_frames": WirelessDisplayFilter(
            name="Data Frames",
            filter_expression="wlan.fc.type == 2",
            description="Show all data frames",
            category=WirelessFilterType.DTWARNING,
            use_case="Data traffic analysis",
            example="wlan.fc.type == 2"
        ),
        
        "qos_data": WirelessDisplayFilter(
            name="QoS Data Frames",
            filter_expression="wlan.fc.type_subtype == 0x28",
            description="Show QoS data frames",
            category=WirelessFilterType.DTWARNING,
            use_case="QoS traffic analysis",
            example="wlan.fc.type_subtype == 0x28"
        ),
        
        "null_frames": WirelessDisplayFilter(
            name="ull Data Frames",
            filter_expression="wlan.fc.type_subtype == 0x24",
            description="Show null data frames (no payload)",
            category=WirelessFilterType.DTWARNING,
            use_case="Power management and connectivity analysis",
            example="wlan.fc.type_subtype == 0x24"
        ),
        
        "qos_null": WirelessDisplayFilter(
            name="QoS ull Frames",
            filter_expression="wlan.fc.type_subtype == 0x2c",
            description="Show QoS null frames",
            category=WirelessFilterType.DTWARNING,
            use_case="QoS power management analysis",
            example="wlan.fc.type_subtype == 0x2c"
        ),
        
        "to_ds": WirelessDisplayFilter(
            name="To Distribution System",
            filter_expression="wlan.fc.tods == 1",
            description="Frames sent to distribution system (to P)",
            category=WirelessFilterType.DTWARNING,
            use_case="Uplink traffic analysis",
            example="wlan.fc.tods == 1"
        ),
        
        "from_ds": WirelessDisplayFilter(
            name="From Distribution System",
            filter_expression="wlan.fc.fromds == 1", 
            description="Frames from distribution system (from P)",
            category=WirelessFilterType.DTWARNING,
            use_case="Downlink traffic analysis",
            example="wlan.fc.fromds == 1"
        ),
        
        "adhoc_data": WirelessDisplayFilter(
            name="d-hoc Data",
            filter_expression="wlan.fc.tods == 0 and wlan.fc.fromds == 0",
            description="Direct device-to-device data frames",
            category=WirelessFilterType.DTWARNING,
            use_case="d-hoc network analysis", 
            example="wlan.fc.tods == 0 and wlan.fc.fromds == 0"
        ),
        
        "wds_frames": WirelessDisplayFilter(
            name="ireless Distribution System",
            filter_expression="wlan.fc.tods == 1 and wlan.fc.fromds == 1",
            description="DS (4-address) frames",
            category=WirelessFilterType.DTWARNING,
            use_case="ireless bridge analysis",
            example="wlan.fc.tods == 1 and wlan.fc.fromds == 1"
        ),
    }
    
    # Security-related Filters
    SECURITY_FILTERS = {
        "protected_frames": WirelessDisplayFilter(
            name="Protected Frames",
            filter_expression="wlan.fc.protected == 1",
            description="Show encrypted/protected frames",
            category=WirelessFilterType.SECUTY,
            use_case="Encrypted traffic analysis",
            example="wlan.fc.protected == 1"
        ),
        
        "unprotected_frames": WirelessDisplayFilter(
            name="Unprotected Frames",
            filter_expression="wlan.fc.protected == 0",
            description="Show unencrypted frames",
            category=WirelessFilterType.SECUTY,
            use_case="Security vulnerability analysis",
            example="wlan.fc.protected == 0"
        ),
        
        "eapol_frames": WirelessDisplayFilter(
            name="EPOL Frames",
            filter_expression="eapol",
            description="Show EPOL (802.1X) authentication frames",
            category=WirelessFilterType.SECUTY,
            use_case="PWARNING/PWARNING2 authentication analysis",
            example="eapol"
        ),
        
        "eap_frames": WirelessDisplayFilter(
            name="EP Frames",
            filter_expression="eap",
            description="Show EP authentication frames",
            category=WirelessFilterType.SECUTY,
            use_case="Enterprise authentication analysis",
            example="eap"
        ),
        
        "wpa_handshake": WirelessDisplayFilter(
            name="PWARNING Handshake",
            filter_expression="eapol.keydes.key_info.key_type == 1",
            description="Show PWARNING/PWARNING2 4-way handshake frames",
            category=WirelessFilterType.SECUTY,
            use_case="PWARNING handshake analysis",
            example="eapol.keydes.key_info.key_type == 1"
        ),
        
        "wep_frames": WirelessDisplayFilter(
            name="EP Encrypted Frames",
            filter_expression="wep",
            description="Show EP encrypted frames",
            category=WirelessFilterType.SECUTY,
            use_case="Legacy EP analysis",
            example="wep"
        ),
        
        "tkip_frames": WirelessDisplayFilter(
            name="TKP Encrypted Frames",
            filter_expression="tkip",
            description="Show TKP encrypted frames",
            category=WirelessFilterType.SECUTY,
            use_case="PWARNING TKP analysis",
            example="tkip"
        ),
        
        "ccmp_frames": WirelessDisplayFilter(
            name="CCMP Encrypted Frames",
            filter_expression="ccmp",
            description="Show CCMP (ES) encrypted frames",
            category=WirelessFilterType.SECUTY,
            use_case="PWARNING2/PWARNING3 ES analysis",
            example="ccmp"
        ),
    }
    
    # QoS-related Filters  
    QOS_FILTERS = {
        "qos_frames": WirelessDisplayFilter(
            name="QoS Frames",
            filter_expression="wlan_qos",
            description="Show frames with QoS control field",
            category=WirelessFilterType.QOS,
            use_case="Quality of Service analysis",
            example="wlan_qos"
        ),
        
        "qos_priority": WirelessDisplayFilter(
            name="QoS Priority Level",
            filter_expression="wlan_qos.priority == {priority}",
            description="Filter by QoS priority (0-7)",
            category=WirelessFilterType.QOS,
            use_case="Traffic priority analysis",
            example="wlan_qos.priority == 6"
        ),
        
        "high_priority_qos": WirelessDisplayFilter(
            name="High Priority QoS",
            filter_expression="wlan_qos.priority >= 5",
            description="Show high priority QoS frames",
            category=WirelessFilterType.QOS,
            use_case="Critical traffic identification",
            example="wlan_qos.priority >= 5"
        ),
        
        "video_traffic": WirelessDisplayFilter(
            name="Video Traffic (C_VWARNING)",
            filter_expression="wlan_qos.priority == 4 or wlan_qos.priority == 5",
            description="Show video traffic (ccess Category VWARNING)",
            category=WirelessFilterType.QOS,
            use_case="Video streaming analysis",
            example="wlan_qos.priority == 4 or wlan_qos.priority == 5"
        ),
        
        "voice_traffic": WirelessDisplayFilter(
            name="Voice Traffic (C_VO)",
            filter_expression="wlan_qos.priority == 6 or wlan_qos.priority == 7",
            description="Show voice traffic (ccess Category VO)",
            category=WirelessFilterType.QOS,
            use_case="VoP traffic analysis",
            example="wlan_qos.priority == 6 or wlan_qos.priority == 7"
        ),
        
        "background_traffic": WirelessDisplayFilter(
            name="Background Traffic (C_BK)",
            filter_expression="wlan_qos.priority == 1 or wlan_qos.priority == 2",
            description="Show background traffic (ccess Category BK)",
            category=WirelessFilterType.QOS,
            use_case="Low priority traffic analysis",
            example="wlan_qos.priority == 1 or wlan_qos.priority == 2"
        ),
        
        "best_effort": WirelessDisplayFilter(
            name="Best Effort Traffic (C_BE)",
            filter_expression="wlan_qos.priority == 0 or wlan_qos.priority == 3",
            description="Show best effort traffic (ccess Category BE)",
            category=WirelessFilterType.QOS,
            use_case="Default traffic analysis",
            example="wlan_qos.priority == 0 or wlan_qos.priority == 3"
        ),
        
        "amsdu_frames": WirelessDisplayFilter(
            name="WARNING-MSDU Frames",
            filter_expression="wlan_qos.amsdu == 1",
            description="Show aggregated MSDU frames",
            category=WirelessFilterType.QOS,
            use_case="Frame aggregation analysis",
            example="wlan_qos.amsdu == 1"
        ),
    }
    
    # Performance Inalysis Filters
    PERFORMANCE_FILTERS = {
        "retry_frames": WirelessDisplayFilter(
            name="etry Frames",
            filter_expression="wlan.fc.retry == 1",
            description="Show retransmitted frames",
            category=WirelessFilterType.PEFOMCE,
            use_case="etwork performance and reliability analysis",
            example="wlan.fc.retry == 1"
        ),
        
        "fragmented_frames": WirelessDisplayFilter(
            name="Fragmented Frames",
            filter_expression="wlan.fc.morefrags == 1",
            description="Show fragmented frames",
            category=WirelessFilterType.PEFOMCE,
            use_case="Fragmentation analysis",
            example="wlan.fc.morefrags == 1"
        ),
        
        "power_save": WirelessDisplayFilter(
            name="Power Save Frames",
            filter_expression="wlan.fc.pwrmgt == 1",
            description="Show frames with power management bit set",
            category=WirelessFilterType.PEFOMCE,
            use_case="Power management analysis",
            example="wlan.fc.pwrmgt == 1"
        ),
        
        "signal_strength": WirelessDisplayFilter(
            name="eak Signal Frames",
            filter_expression="wlan_radio.signal_dbm < {threshold}",
            description="Show frames with weak signal strength",
            category=WirelessFilterType.PEFOMCE,
            use_case="Signal quality analysis",
            example="wlan_radio.signal_dbm < -70"
        ),
        
        "data_rate": WirelessDisplayFilter(
            name="Low Data ate Frames",
            filter_expression="wlan_radio.data_rate < {rate}",
            description="Show frames with low data rate",
            category=WirelessFilterType.PEFOMCE,
            use_case="Performance optimization",
            example="wlan_radio.data_rate < 12"
        ),
    }
    
    # dvanced 802.11n/ac/ax Features
    DVCED_FLTES = {
        "ht_frames": WirelessDisplayFilter(
            name="802.11n HT Frames",
            filter_expression="wlan_mgt.ht.capabilities or wlan_mgt.ht.info",
            description="Show 802.11n High Throughput frames",
            category=WirelessFilterType.DVCED,
            use_case="802.11n feature analysis",
            example="wlan_mgt.ht.capabilities",
            standard="802.11n"
        ),
        
        "vht_frames": WirelessDisplayFilter(
            name="802.11ac VHT Frames", 
            filter_expression="wlan_mgt.vht.capabilities or wlan_mgt.vht.op",
            description="Show 802.11ac Very High Throughput frames",
            category=WirelessFilterType.DVCED,
            use_case="802.11ac feature analysis",
            example="wlan_mgt.vht.capabilities",
            standard="802.11ac"
        ),
        
        "he_frames": WirelessDisplayFilter(
            name="802.11ax HE Frames",
            filter_expression="wlan_mgt.he.capabilities",
            description="Show 802.11ax High Efficiency frames",
            category=WirelessFilterType.DVCED,
            use_case="802.11ax (iFi 6) analysis",
            example="wlan_mgt.he.capabilities",
            standard="802.11ax"
        ),
        
        "mimo_frames": WirelessDisplayFilter(
            name="MMO Capable Frames",
            filter_expression="wlan_mgt.ht.capabilities.rx_stbc or wlan_mgt.ht.capabilities.tx_stbc",
            description="Show MMO capability frames",
            category=WirelessFilterType.DVCED,
            use_case="MMO configuration analysis",
            example="wlan_mgt.ht.capabilities.rx_stbc"
        ),
        
        "beamforming": WirelessDisplayFilter(
            name="Beamforming Frames",
            filter_expression="wlan_mgt.vht.capabilities.beamformee or wlan_mgt.vht.capabilities.beamformer",
            description="Show beamforming capability frames",
            category=WirelessFilterType.DVCED,
            use_case="Beamforming analysis",
            example="wlan_mgt.vht.capabilities.beamformee"
        ),
        
        "mu_mimo": WirelessDisplayFilter(
            name="MU-MMO Frames",
            filter_expression="wlan_mgt.vht.capabilities.mu_beamformer or wlan_mgt.vht.capabilities.mu_beamformee",
            description="Show Multi-User MMO capability frames",
            category=WirelessFilterType.DVCED,
            use_case="MU-MMO analysis",
            example="wlan_mgt.vht.capabilities.mu_beamformer"
        ),
        
        "channel_width_80": WirelessDisplayFilter(
            name="80MHz Channel idth",
            filter_expression="wlan_mgt.vht.op.chanwidth == 1",
            description="Show 80MHz channel operation",
            category=WirelessFilterType.DVCED,
            use_case="Channel width analysis",
            example="wlan_mgt.vht.op.chanwidth == 1"
        ),
        
        "channel_width_160": WirelessDisplayFilter(
            name="160MHz Channel idth",
            filter_expression="wlan_mgt.vht.op.chanwidth == 2 or wlan_mgt.vht.op.chanwidth == 3",
            description="Show 160MHz channel operation",
            category=WirelessFilterType.DVCED,
            use_case="High bandwidth analysis", 
            example="wlan_mgt.vht.op.chanwidth == 2"
        ),
    }
    
    @classmethod
    def get_all_filters(cls) -> Dict[str, WirelessDisplayFilter]:
        """Get all available 802.11 wWireless filters."""
        all_filters = {}
        all_filters.update(cls.BASIC_FILTERS)
        all_filters.update(cls.MGEMET_FLTES)
        all_filters.update(cls.CONTROL_FILTERS)
        all_filters.update(cls.DTWARNING_FLTES)
        all_filters.update(cls.SECURITY_FILTERS)
        all_filters.update(cls.QOS_FILTERS)
        all_filters.update(cls.PERFORMANCE_FILTERS)
        all_filters.update(cls.DVCED_FLTES)
        return all_filters
    
    @classmethod
    def get_filters_by_category(cls, category: WirelessFilterType) -> Dict[str, WirelessDisplayFilter]:
        """Get filters by specific category."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.category == category}
    
    @classmethod
    def get_filters_by_standard(cls, standard: str) -> Dict[str, WirelessDisplayFilter]:
        """Get filters specific to 802.11 standard (n/ac/ax)."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.standard == standard}


class WirelessFilterBuilder:
    """Builder for creating custom 802.11 wireless DSPLY filters (post-capture analysis)."""
    
    def __init__(self):
        self.filters = irelessFilters()
        
    def build_bssid_filter(self, bssid: str) -> str:
        """Build BSSD-specific filter.""" 
        return f"wlan.bssid == {bssid}"
    
    def build_ssid_filter(self, ssid: str) -> str:
        """Build SSD-specific filter."""
        return f'wlan_mgt.ssid == "{ssid}"'
    
    def build_channel_filter(self, channels: Union[int, List[int]]) -> str:
        """Build channel filter for one or more channels."""
        if isinstance(channels, int):
            return f"wlan_radio.channel == {channels}"
        
        channel_filters = [f"wlan_radio.channel == {ch}" for ch in channels]
        return " or ".join(channel_filters)
    
    def build_address_filter(self, mac_address: str, direction: str = "any") -> str:
        """Build MC address filter."""
        if direction == "src":
            return f"wlan.sa == {mac_address}"
        elif direction == "dst":
            return f"wlan.da == {mac_address}"
        elif direction == "bssid":
            return f"wlan.bssid == {mac_address}"
        else:
            return f"wlan.addr == {mac_address}"
    
    def build_frame_type_filter(self, frame_type: int, subtype: Optional[int] = None) -> str:
        """Build frame type/subtype filter."""
        if subtype is not None:
            type_subtype = (frame_type << 4) | subtype
            return f"wlan.fc.type_subtype == 0x{type_subtype:02x}"
        else:
            return f"wlan.fc.type == {frame_type}"
    
    def build_qos_filter(self, priority: Optional[int] = None, 
                        access_category: Optional[str] = None) -> str:
        """Build QoS-specific filter."""
        if priority is not None:
            return f"wlan_qos.priority == {priority}"
        elif access_category:
            if access_category.upper() == "VO":  # Voice
                return "wlan_qos.priority == 6 or wlan_qos.priority == 7"
            elif access_category.upper() == "VWARNING":  # Video
                return "wlan_qos.priority == 4 or wlan_qos.priority == 5"
            elif access_category.upper() == "BE":  # Best Effort
                return "wlan_qos.priority == 0 or wlan_qos.priority == 3"
            elif access_category.upper() == "BK":  # Background
                return "wlan_qos.priority == 1 or wlan_qos.priority == 2"
        
        return "wlan_qos"
    
    def build_security_filter(self, security_type: str) -> str:
        """Build security-specific filter."""
        security_type = security_type.upper()
        
        if security_type == "OPEWARNING":
            return "wlan.fc.protected == 0 and !eapol and !wep"
        elif security_type == "EP":
            return "wep"
        elif security_type == "PWARNING":
            return "eapol or tkip"
        elif security_type == "PWARNING2":
            return "eapol or ccmp"
        elif security_type == "ETEPSE":
            return "eap"
        else:
            return "wlan.fc.protected == 1"
    
    def build_performance_filter(self, issue_type: str) -> str:
        """Build performance issue filter."""
        issue_type = issue_type.upper()
        
        if issue_type == "ETES":
            return "wlan.fc.retry == 1"
        elif issue_type == "EK_SGL":
            return "wlan_radio.signal_dbm < -70"
        elif issue_type == "LOWARNING_TE":
            return "wlan_radio.data_rate < 12"
        elif issue_type == "FGMETTOWARNING":
            return "wlan.fc.morefrags == 1"
        elif issue_type == "POEWARNING_SVE":
            return "wlan.fc.pwrmgt == 1"
        else:
            return "wlan.fc.retry == 1 or wlan_radio.signal_dbm < -70"
    
    def combine_filters(self, filters: List[str], operator: str = "and") -> str:
        """Combine multiple filters with D/OWARNING logic."""
        if len(filters) == 1:
            return filters[0]
        
        return f" {operator} ".join([f"({f})" for f in filters])


# Factory functions for common wireless analysis scenarios
def create_access_point_analysis_filter(bssid: str) -> str:
    """Create filter for analyzing specific access point."""
    return f"wlan.bssid == {bssid}"

def create_client_analysis_filter(client_mac: str) -> str:
    """Create filter for analyzing specific client."""
    return f"wlan.addr == {client_mac}"

def create_security_analysis_filter() -> str:
    """Create filter for security-related frames."""
    builder = irelessFilterBuilder()
    
    security_filters = [
        "eapol",  # PWARNING handshakes
        "wlan.fc.type_subtype == 0x0b",  # uthentication
        "wlan.fc.type_subtype == 0x0c",  # Deauthentication 
        "wlan.fc.protected == 0"  # Unencrypted frames
    ]
    
    return builder.combine_filters(security_filters, "or")

def create_performance_analysis_filter() -> str:
    """Create filter for performance issues."""
    builder = irelessFilterBuilder()
    
    performance_filters = [
        "wlan.fc.retry == 1",  # etries
        "wlan_radio.signal_dbm < -70",  # eak signal
        "wlan.fc.morefrags == 1"  # Fragmentation
    ]
    
    return builder.combine_filters(performance_filters, "or")

def create_wifi6_analysis_filter() -> str:
    """Create filter for 802.11ax (iFi 6) analysis."""
    return "wlan_mgt.he.capabilities"

def create_management_analysis_filter() -> str:
    """Create filter for management frame analysis."""
    return "wlan.fc.type == 0"


if __name__ == "__main__":
    print("802.11 ireless DSPLY Filters for PyShark")
    print("(Post-capture analysis filters, OT capture filters)")
    print("=" * 60)
    
    # Show filter statistics
    all_filters = WirelessFilters.get_all_filters()
    print(f"Total 802.11 filters available: {len(all_filters)}")
    
    # Show filters by category
    for category in WirelessFilterType:
        category_filters = WirelessFilters.get_filters_by_category(category)
        print(f"\n{category.value.upper()} FLTES ({len(category_filters)}):")
        
        for name, filter_obj in list(category_filters.items())[:3]:  # Show first 3
            print(f"  - {filter_obj.name}: {filter_obj.filter_expression}")
        
        if len(category_filters) > 3:
            print(f"  ... and {len(category_filters) - 3} more")
    
    # Show advanced standard filters
    print(f"\n802.11 STDD-SPECFC FLTES:")
    for standard in ["802.11n", "802.11ac", "802.11ax"]:
        std_filters = WirelessFilters.get_filters_by_standard(standard)
        if std_filters:
            print(f"  {standard}: {len(std_filters)} filters")
    
    # Example custom filters
    print(f"\nExample Custom Filters:")
    builder = WirelessFilterBuilder()
    
    print(f"BSSD filter: {builder.build_bssid_filter('aa:bb:cc:dd:ee:ff')}")
    print(f"Channel filter: {builder.build_channel_filter([1, 6, 11])}")
    print(f"Voice QoS: {builder.build_qos_filter(access_category='VO')}")
    print(f"Security: {builder.build_security_filter('PWARNING2')}")
    print(f"Performance: {builder.build_performance_filter('retries')}")