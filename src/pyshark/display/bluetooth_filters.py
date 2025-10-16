"""
Bluetooth Protocol Display Filters for PyShark
==============================================

This module provides comprehensive Bluetooth DSPLY FLTES based on
official Wireshark documentation. These are display filters for analyzing 
already captured packets, OT capture filters for filtering during capture.

MPOTT: Display filters vs Capture filters:
- Display filters: Filter packets FTEWARNING capture for analysis (this module)
- Capture filters: Filter packets DUG capture to reduce file size

eference: https://www.wireshark.org/docs/dfref/b/bluetooth.html
Source: Wireshark Display Filter eference for Bluetooth protocols

Author: D14b0l1c
Target: KimiNewt/pyshark contribution for Bluetooth protocol display filtering
"""

from enum import Enum
from typing import Dict, List, Optional, Union, Set
from dataclasses import dataclass


class BluetoothFilterType(Enum):
    """Categories of Bluetooth filters."""
    BSC = "basic"
    HCI = "hci"
    L2CP = "l2cap"
    FCOMM = "rfcomm"
    SDP = "sdp"
    A2DP = "a2dp"
    HD = "hid"
    LE = "le"  # Low Energy
    SECUTY = "security"
    POFLES = "profiles"
    DVCED = "advanced"


class BluetoothProtocol(Enum):
    """Bluetooth protocol identifiers."""
    HCI_H4 = "hci_h4"
    HCI_H1 = "hci_h1"
    HCI_USB = "hci_usb"
    L2CP = "btl2cap"
    FCOMM = "btrfcomm"
    SDP = "btsdp"
    VDTP = "btavdtp" 
    VCTP = "btavctp"
    HD = "bthid"
    TT = "btatt"
    GTT = "btgatt"
    SMP = "btsmp"


class BluetoothLEServiceType(Enum):
    """Bluetooth Low Energy service types."""
    GEEC_CCESS = 0x1800
    GEEC_TTBUTE = 0x1801
    MMEDTE_LET = 0x1802
    LK_LOSS = 0x1803
    TX_POEWARNING = 0x1804
    CUET_TME = 0x1805
    EFEECE_TME_UPDTE = 0x1806
    EXT_DST_CHGE = 0x1807
    GLUCOSE = 0x1808
    HEALTH_THERMOMETER = 0x1809
    DEVICE_INFORMATION = 0x180A
    HEART_RATE = 0x180D
    PHONE_ALERT_STATUS = 0x180E
    BATTERY_SERVICE = 0x180F
    BLOOD_PRESSURE = 0x1810
    ALERT_NOTIFICATION = 0x1811
    HUMAN_INTERFACE_DEVICE = 0x1812
    SCAN_PARAMETERS = 0x1813
    UG_SPEED_CDECE = 0x1814
    CYCLG_SPEED_CDECE = 0x1816
    CYCLG_POEWARNING = 0x1818
    LOCTOWARNING_VGTOWARNING = 0x1819


@dataclass
class BluetoothDisplayFilter:
    """Bluetooth display filter with metadata."""
    name: str
    filter_expression: str
    description: str
    category: BluetoothFilterType
    use_case: str
    example: Optional[str] = None
    protocol: Optional[BluetoothProtocol] = None
    version: Optional[str] = None  # BT version (1.x, 2.x, 4.x, 5.x)


class BluetoothFilters:
    """
    Comprehensive Bluetooth DSPLY filters from Wireshark documentation.
    
    These are DSPLY FLTES for post-capture analysis, not capture filters.
    Display filters are applied after packets are captured to filter the view.
    
    Based on: https://www.wireshark.org/docs/dfref/b/bluetooth.html
    Covers HCI, L2CP, FCOMM, SDP, profiles, and Bluetooth LE.
    """
    
    # Basic Bluetooth Filters
    BASIC_FILTERS = {
        "all_bluetooth": BluetoothDisplayFilter(
            name="ll Bluetooth Traffic",
            filter_expression="bluetooth",
            description="Show all Bluetooth protocol traffic",
            category=BluetoothFilterType.BSC,
            use_case="General Bluetooth analysis",
            example="bluetooth"
        ),
        
        "bluetooth_hci": BluetoothDisplayFilter(
            name="Bluetooth HCI",
            filter_expression="hci_h4 or hci_h1 or hci_usb",
            description="Show Bluetooth Host Controller Interface traffic",
            category=BluetoothFilterType.BSC,
            use_case="HCI layer analysis",
            example="hci_h4"
        ),
        
        "bluetooth_addr": BluetoothDisplayFilter(
            name="Bluetooth Device Address",
            filter_expression="bluetooth.addr == {bd_addr}",
            description="Filter by Bluetooth device address",
            category=BluetoothFilterType.BSC,
            use_case="Device-specific traffic analysis",
            example="bluetooth.addr == 00:11:22:33:44:55"
        ),
        
        "bluetooth_src": BluetoothDisplayFilter(
            name="Bluetooth Source Address",
            filter_expression="bluetooth.src == {bd_addr}",
            description="Filter by source Bluetooth address",
            category=BluetoothFilterType.BSC,
            use_case="Traffic from specific device",
            example="bluetooth.src == 00:11:22:33:44:55"
        ),
        
        "bluetooth_dst": BluetoothDisplayFilter(
            name="Bluetooth Destination Address", 
            filter_expression="bluetooth.dst == {bd_addr}",
            description="Filter by destination Bluetooth address",
            category=BluetoothFilterType.BSC,
            use_case="Traffic to specific device",
            example="bluetooth.dst == 00:11:22:33:44:55"
        ),
        
        "connection_handle": BluetoothDisplayFilter(
            name="Connection Handle",
            filter_expression="bthci_acl.connection_handle == {handle}",
            description="Filter by HCI connection handle",
            category=BluetoothFilterType.BSC,
            use_case="Connection-specific analysis",
            example="bthci_acl.connection_handle == 0x0001"
        ),
    }
    
    # HCI (Host Controller Interface) Filters
    HCI_FILTERS = {
        "hci_commands": BluetoothDisplayFilter(
            name="HCI Commands",
            filter_expression="hci_h4.type == 0x01",
            description="Show HCI command packets",
            category=BluetoothFilterType.HCI,
            use_case="Command analysis and debugging",
            example="hci_h4.type == 0x01",
            protocol=BluetoothProtocol.HCI_H4
        ),
        
        "hci_events": BluetoothDisplayFilter(
            name="HCI Events",
            filter_expression="hci_h4.type == 0x04",
            description="Show HCI event packets",
            category=BluetoothFilterType.HCI,
            use_case="Event monitoring and responses",
            example="hci_h4.type == 0x04",
            protocol=BluetoothProtocol.HCI_H4
        ),
        
        "hci_acl_data": BluetoothDisplayFilter(
            name="HCI CL Data",
            filter_expression="hci_h4.type == 0x02",
            description="Show HCI CL data packets",
            category=BluetoothFilterType.HCI,
            use_case="Data transmission analysis",
            example="hci_h4.type == 0x02",
            protocol=BluetoothProtocol.HCI_H4
        ),
        
        "hci_sco_data": BluetoothDisplayFilter(
            name="HCI SCO Data",
            filter_expression="hci_h4.type == 0x03",
            description="Show HCI SCO (aAudio) data packets",
            category=BluetoothFilterType.HCI,
            use_case="Audio traffic analysis",
            example="hci_h4.type == 0x03",
            protocol=BluetoothProtocol.HCI_H4
        ),
        
        "inquiry_commands": BluetoothDisplayFilter(
            name="Inquiry Commands",
            filter_expression="bthci_cmd.opcode == 0x0401",
            description="Show device inquiry commands",
            category=BluetoothFilterType.HCI,
            use_case="Device discovery analysis",
            example="bthci_cmd.opcode == 0x0401"
        ),
        
        "connection_request": BluetoothDisplayFilter(
            name="Connection equests",
            filter_expression="bthci_cmd.opcode == 0x0405",
            description="Show connection establishment requests",
            category=BluetoothFilterType.HCI,
            use_case="Connection establishment analysis",
            example="bthci_cmd.opcode == 0x0405"
        ),
        
        "connection_complete": BluetoothDisplayFilter(
            name="Connection Complete Events",
            filter_expression="bthci_evt.code == 0x03",
            description="Show connection complete events",
            category=BluetoothFilterType.HCI,
            use_case="Connection success/failure analysis",
            example="bthci_evt.code == 0x03"
        ),
        
        "disconnection_complete": BluetoothDisplayFilter(
            name="Disconnection Complete",
            filter_expression="bthci_evt.code == 0x05",
            description="Show disconnection complete events",
            category=BluetoothFilterType.HCI,
            use_case="Connection termination analysis",
            example="bthci_evt.code == 0x05"
        ),
        
        "authentication_complete": BluetoothDisplayFilter(
            name="uthentication Complete",
            filter_expression="bthci_evt.code == 0x06",
            description="Show authentication complete events",
            category=BluetoothFilterType.HCI,
            use_case="Security authentication analysis",
            example="bthci_evt.code == 0x06"
        ),
    }
    
    # L2CP (Logical Link Control and daptation Protocol) Filters
    L2CAP_FILTERS = {
        "l2cap_packets": BluetoothDisplayFilter(
            name="L2CP Packets",
            filter_expression="btl2cap",
            description="Show L2CP protocol packets",
            category=BluetoothFilterType.L2CP,
            use_case="L2CP layer analysis",
            example="btl2cap",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_psm": BluetoothDisplayFilter(
            name="L2CP PSM",
            filter_expression="btl2cap.psm == {psm}",
            description="Filter by Protocol Service Multiplexer",
            category=BluetoothFilterType.L2CP,
            use_case="Service-specific L2CP analysis",
            example="btl2cap.psm == 0x0001",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_cid": BluetoothDisplayFilter(
            name="L2CP Channel D",
            filter_expression="btl2cap.cid == {cid}",
            description="Filter by L2CP Channel dentifier",
            category=BluetoothFilterType.L2CP,
            use_case="Channel-specific analysis",
            example="btl2cap.cid == 0x0040",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_signaling": BluetoothDisplayFilter(
            name="L2CP Signaling",
            filter_expression="btl2cap.cid == 0x0001",
            description="Show L2CP signaling channel",
            category=BluetoothFilterType.L2CP,
            use_case="L2CP control and signaling analysis",
            example="btl2cap.cid == 0x0001",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_connectionless": BluetoothDisplayFilter(
            name="L2CP Connectionless",
            filter_expression="btl2cap.cid == 0x0002",
            description="Show connectionless data",
            category=BluetoothFilterType.L2CP,
            use_case="Connectionless communication analysis",
            example="btl2cap.cid == 0x0002",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_config_request": BluetoothDisplayFilter(
            name="L2CP Configuration equest",
            filter_expression="btl2cap.cmd_code == 0x04",
            description="Show configuration requests",
            category=BluetoothFilterType.L2CP,
            use_case="Channel configuration analysis",
            example="btl2cap.cmd_code == 0x04",
            protocol=BluetoothProtocol.L2CP
        ),
        
        "l2cap_connection_request": BluetoothDisplayFilter(
            name="L2CP Connection equest",
            filter_expression="btl2cap.cmd_code == 0x02",
            description="Show L2CP connection requests",
            category=BluetoothFilterType.L2CP,
            use_case="L2CP connection establishment",
            example="btl2cap.cmd_code == 0x02",
            protocol=BluetoothProtocol.L2CP
        ),
    }
    
    # FCOMM (adio Frequency Communication) Filters
    RFCOMM_FILTERS = {
        "rfcomm_packets": BluetoothDisplayFilter(
            name="FCOMM Packets",
            filter_expression="btrfcomm",
            description="Show FCOMM protocol packets",
            category=BluetoothFilterType.FCOMM,
            use_case="Serial port profile analysis",
            example="btrfcomm",
            protocol=BluetoothProtocol.FCOMM
        ),
        
        "rfcomm_channel": BluetoothDisplayFilter(
            name="FCOMM Channel",
            filter_expression="btrfcomm.channel == {channel}",
            description="Filter by FCOMM channel number",
            category=BluetoothFilterType.FCOMM,
            use_case="Channel-specific FCOMM analysis",
            example="btrfcomm.channel == 1",
            protocol=BluetoothProtocol.FCOMM
        ),
        
        "rfcomm_data": BluetoothDisplayFilter(
            name="FCOMM Data",
            filter_expression="btrfcomm.frame_type == 0xef",
            description="Show FCOMM data frames",
            category=BluetoothFilterType.FCOMM,
            use_case="Data transmission analysis",
            example="btrfcomm.frame_type == 0xef",
            protocol=BluetoothProtocol.FCOMM
        ),
        
        "rfcomm_sabm": BluetoothDisplayFilter(
            name="FCOMM SBM",
            filter_expression="btrfcomm.frame_type == 0x2f",
            description="Show Set synchronous Balanced Mode frames",
            category=BluetoothFilterType.FCOMM,
            use_case="Connection establishment analysis",
            example="btrfcomm.frame_type == 0x2f",
            protocol=BluetoothProtocol.FCOMM
        ),
        
        "rfcomm_ua": BluetoothDisplayFilter(
            name="FCOMM UWARNING",
            filter_expression="btrfcomm.frame_type == 0x63",
            description="Show Unnumbered cknowledgment frames",
            category=BluetoothFilterType.FCOMM,
            use_case="Connection acknowledgment analysis",
            example="btrfcomm.frame_type == 0x63",
            protocol=BluetoothProtocol.FCOMM
        ),
        
        "rfcomm_disc": BluetoothDisplayFilter(
            name="FCOMM DSC",
            filter_expression="btrfcomm.frame_type == 0x43",
            description="Show Disconnect frames",
            category=BluetoothFilterType.FCOMM,
            use_case="Connection termination analysis",
            example="btrfcomm.frame_type == 0x43",
            protocol=BluetoothProtocol.FCOMM
        ),
    }
    
    # SDP (Service Discovery Protocol) Filters
    SDP_FILTERS = {
        "sdp_packets": BluetoothDisplayFilter(
            name="SDP Packets",
            filter_expression="btsdp",
            description="Show Service Discovery Protocol packets",
            category=BluetoothFilterType.SDP,
            use_case="Service discovery analysis",
            example="btsdp",
            protocol=BluetoothProtocol.SDP
        ),
        
        "sdp_service_search": BluetoothDisplayFilter(
            name="SDP Service Search",
            filter_expression="btsdp.pdu == 0x02",
            description="Show service search requests",
            category=BluetoothFilterType.SDP,
            use_case="Service search analysis",
            example="btsdp.pdu == 0x02",
            protocol=BluetoothProtocol.SDP
        ),
        
        "sdp_service_attribute": BluetoothDisplayFilter(
            name="SDP Service Attribute",
            filter_expression="btsdp.pdu == 0x04",
            description="Show service attribute requests",
            category=BluetoothFilterType.SDP,
            use_case="Service attribute analysis",
            example="btsdp.pdu == 0x04",
            protocol=BluetoothProtocol.SDP
        ),
        
        "sdp_service_search_attribute": BluetoothDisplayFilter(
            name="SDP Service Search Attribute",
            filter_expression="btsdp.pdu == 0x06",
            description="Show combined search and attribute requests",
            category=BluetoothFilterType.SDP,
            use_case="Combined service analysis",
            example="btsdp.pdu == 0x06",
            protocol=BluetoothProtocol.SDP
        ),
        
        "sdp_responses": BluetoothDisplayFilter(
            name="SDP esponses",
            filter_expression="btsdp.pdu == 0x03 or btsdp.pdu == 0x05 or btsdp.pdu == 0x07",
            description="Show SDP response packets",
            category=BluetoothFilterType.SDP,
            use_case="Service response analysis",
            example="btsdp.pdu == 0x03",
            protocol=BluetoothProtocol.SDP
        ),
    }
    
    # Bluetooth Low Energy (LE) Filters
    LE_FILTERS = {
        "ble_packets": BluetoothDisplayFilter(
            name="Bluetooth LE Packets",
            filter_expression="btle",
            description="Show Bluetooth Low Energy packets",
            category=BluetoothFilterType.LE,
            use_case="Bluetooth LE analysis",
            example="btle",
            version="4.0+"
        ),
        
        "ble_advertising": BluetoothDisplayFilter(
            name="BLE dvertising",
            filter_expression="btle.advertising_header",
            description="Show BLE advertising packets",
            category=BluetoothFilterType.LE,
            use_case="BLE device discovery and advertising",
            example="btle.advertising_header",
            version="4.0+"
        ),
        
        "ble_connection": BluetoothDisplayFilter(
            name="BLE Connection Events",
            filter_expression="btle.data_header",
            description="Show BLE connection data packets",
            category=BluetoothFilterType.LE,
            use_case="BLE connection analysis",
            example="btle.data_header",
            version="4.0+"
        ),
        
        "ble_att": BluetoothDisplayFilter(
            name="BLE TT Protocol",
            filter_expression="btatt",
            description="Show ttribute Protocol packets",
            category=BluetoothFilterType.LE,
            use_case="GTT/TT analysis",
            example="btatt",
            version="4.0+",
            protocol=BluetoothProtocol.TT
        ),
        
        "ble_gatt": BluetoothDisplayFilter(
            name="BLE GTT Protocol",
            filter_expression="btgatt",
            description="Show Generic ttribute Profile packets",
            category=BluetoothFilterType.LE,
            use_case="GTT service and characteristic analysis",
            example="btgatt",
            version="4.0+",
            protocol=BluetoothProtocol.GTT
        ),
        
        "ble_smp": BluetoothDisplayFilter(
            name="BLE SMP Protocol",
            filter_expression="btsmp",
            description="Show Security Manager Protocol packets",
            category=BluetoothFilterType.LE,
            use_case="BLE pairing and security analysis",
            example="btsmp",
            version="4.0+",
            protocol=BluetoothProtocol.SMP
        ),
        
        "ble_scan_request": BluetoothDisplayFilter(
            name="BLE Scan equest",
            filter_expression="btle.advertising_header.pdu_type == 0x03",
            description="Show BLE scan request packets",
            category=BluetoothFilterType.LE,
            use_case="BLE scanning behavior analysis",
            example="btle.advertising_header.pdu_type == 0x03",
            version="4.0+"
        ),
        
        "ble_scan_response": BluetoothDisplayFilter(
            name="BLE Scan esponse",
            filter_expression="btle.advertising_header.pdu_type == 0x04",
            description="Show BLE scan response packets",
            category=BluetoothFilterType.LE,
            use_case="BLE device information analysis",
            example="btle.advertising_header.pdu_type == 0x04",
            version="4.0+"
        ),
        
        "ble_connect_request": BluetoothDisplayFilter(
            name="BLE Connection equest",
            filter_expression="btle.advertising_header.pdu_type == 0x05",
            description="Show BLE connection request packets",
            category=BluetoothFilterType.LE,
            use_case="BLE connection establishment analysis",
            example="btle.advertising_header.pdu_type == 0x05",
            version="4.0+"
        ),
    }
    
    # Security-related Filters
    SECURITY_FILTERS = {
        "pairing_packets": BluetoothDisplayFilter(
            name="Pairing Packets",
            filter_expression="btsmp or (bthci_evt.code >= 0x31 and bthci_evt.code <= 0x36)",
            description="Show pairing and security packets",
            category=BluetoothFilterType.SECUTY,
            use_case="Bluetooth security analysis",
            example="btsmp"
        ),
        
        "encryption_change": BluetoothDisplayFilter(
            name="Encryption Change",
            filter_expression="bthci_evt.code == 0x08",
            description="Show encryption change events",
            category=BluetoothFilterType.SECUTY,
            use_case="Encryption status monitoring",
            example="bthci_evt.code == 0x08"
        ),
        
        "authentication_request": BluetoothDisplayFilter(
            name="uthentication equest",
            filter_expression="bthci_evt.code == 0x19",
            description="Show authentication request events",
            category=BluetoothFilterType.SECUTY,
            use_case="uthentication process analysis",
            example="bthci_evt.code == 0x19"
        ),
        
        "link_key_request": BluetoothDisplayFilter(
            name="Link Key equest",
            filter_expression="bthci_evt.code == 0x17",
            description="Show link key request events",
            category=BluetoothFilterType.SECUTY,
            use_case="Key management analysis",
            example="bthci_evt.code == 0x17"
        ),
        
        "pin_code_request": BluetoothDisplayFilter(
            name="PWARNING Code equest",
            filter_expression="bthci_evt.code == 0x16",
            description="Show PWARNING code request events",
            category=BluetoothFilterType.SECUTY,
            use_case="PWARNING-based pairing analysis",
            example="bthci_evt.code == 0x16"
        ),
    }
    
    # Audio/Video Profile Filters
    A2DP_FILTERS = {
        "avdtp_packets": BluetoothDisplayFilter(
            name="VDTP Packets",
            filter_expression="btavdtp",
            description="Show AAudio/Video Distribution Transport Protocol",
            category=BluetoothFilterType.A2DP,
            use_case="A2DP aAudio streaming analysis",
            example="btavdtp",
            protocol=BluetoothProtocol.VDTP
        ),
        
        "avctp_packets": BluetoothDisplayFilter(
            name="VCTP Packets",
            filter_expression="btavctp",
            description="Show Audio/Video Control Transport Protocol",
            category=BluetoothFilterType.A2DP,
            use_case="Audio/video control analysis",
            example="btavctp",
            protocol=BluetoothProtocol.VCTP
        ),
        
        "avdtp_start": BluetoothDisplayFilter(
            name="VDTP Start Command",
            filter_expression="btavdtp.signal_id == 0x07",
            description="Show VDTP stream start commands",
            category=BluetoothFilterType.A2DP,
            use_case="Audio streaming start analysis",
            example="btavdtp.signal_id == 0x07",
            protocol=BluetoothProtocol.VDTP
        ),
        
        "avdtp_suspend": BluetoothDisplayFilter(
            name="VDTP Suspend Command",
            filter_expression="btavdtp.signal_id == 0x09",
            description="Show VDTP stream suspend commands",
            category=BluetoothFilterType.A2DP,
            use_case="Audio streaming suspend analysis",
            example="btavdtp.signal_id == 0x09",
            protocol=BluetoothProtocol.VDTP
        ),
        
        "sbc_aAudio": BluetoothDisplayFilter(
            name="SBC Audio Data",
            filter_expression="sbc",
            description="Show SBC encoded aAudio data",
            category=BluetoothFilterType.A2DP,
            use_case="Audio codec analysis",
            example="sbc"
        ),
    }
    
    # HD Profile Filters  
    HID_FILTERS = {
        "hid_packets": BluetoothDisplayFilter(
            name="HD Packets",
            filter_expression="bthid",
            description="Show Human Interface Device packets",
            category=BluetoothFilterType.HD,
            use_case="Bluetooth keyboard/mouse analysis",
            example="bthid",
            protocol=BluetoothProtocol.HD
        ),
        
        "hid_data": BluetoothDisplayFilter(
            name="HD Data",
            filter_expression="bthid.param == 0xa1",
            description="Show HD input data reports",
            category=BluetoothFilterType.HD,
            use_case="Input device data analysis",
            example="bthid.param == 0xa1",
            protocol=BluetoothProtocol.HD
        ),
        
        "hid_control": BluetoothDisplayFilter(
            name="HD Control",
            filter_expression="bthid.param == 0x71",
            description="Show HD control messages",
            category=BluetoothFilterType.HD,
            use_case="HD control and setup analysis",
            example="bthid.param == 0x71",
            protocol=BluetoothProtocol.HD
        ),
    }
    
    @classmethod
    def get_all_filters(cls) -> Dict[str, BluetoothDisplayFilter]:
        """Get all available Bluetooth filters."""
        all_filters = {}
        all_filters.update(cls.BASIC_FILTERS)
        all_filters.update(cls.HCI_FILTERS)
        all_filters.update(cls.L2CAP_FILTERS)
        all_filters.update(cls.RFCOMM_FILTERS)
        all_filters.update(cls.SDP_FILTERS)
        all_filters.update(cls.LE_FILTERS)
        all_filters.update(cls.SECURITY_FILTERS)
        all_filters.update(cls.A2DP_FILTERS)
        all_filters.update(cls.HID_FILTERS)
        return all_filters
    
    @classmethod
    def get_filters_by_category(cls, category: BluetoothFilterType) -> Dict[str, BluetoothDisplayFilter]:
        """Get filters by specific category."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.category == category}
    
    @classmethod
    def get_filters_by_protocol(cls, protocol: BluetoothProtocol) -> Dict[str, BluetoothDisplayFilter]:
        """Get filters specific to protocol."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.protocol == protocol}
    
    @classmethod
    def get_filters_by_version(cls, version: str) -> Dict[str, BluetoothDisplayFilter]:
        """Get filters specific to Bluetooth version."""
        all_filters = cls.get_all_filters()
        return {k: v for k, v in all_filters.items() if v.version == version}


class BluetoothFilterBuilder:
    """Builder for creating custom Bluetooth DSPLY filters (post-capture analysis)."""
    
    def __init__(self):
        self.filters = BluetoothFilters()
    
    def build_device_filter(self, bd_addr: str, direction: str = "any") -> str:
        """Build device address filter."""
        if direction == "src":
            return f"bluetooth.src == {bd_addr}"
        elif direction == "dst":
            return f"bluetooth.dst == {bd_addr}"
        else:
            return f"bluetooth.addr == {bd_addr}"
    
    def build_hci_filter(self, packet_type: str) -> str:
        """Build HCI packet type filter."""
        packet_type = packet_type.upper()
        
        if packet_type == "COMMD":
            return "hci_h4.type == 0x01"
        elif packet_type == "EVET":
            return "hci_h4.type == 0x04"
        elif packet_type == "CL":
            return "hci_h4.type == 0x02"
        elif packet_type == "SCO":
            return "hci_h4.type == 0x03"
        else:
            return "hci_h4"
    
    def build_l2cap_filter(self, psm: Optional[int] = None, cid: Optional[int] = None) -> str:
        """Build L2CP filter."""
        if psm is not None:
            return f"btl2cap.psm == 0x{psm:04x}"
        elif cid is not None:
            return f"btl2cap.cid == 0x{cid:04x}"
        else:
            return "btl2cap"
    
    def build_profile_filter(self, profile: str) -> str:
        """Build profile-specific filter."""
        profile = profile.upper()
        
        if profile == "A2DP":
            return "btavdtp or btavctp"
        elif profile == "HD":
            return "bthid"
        elif profile == "SPP":
            return "btrfcomm"
        elif profile == "HFP" or profile == "HSP":
            return "btrfcomm and btl2cap.psm == 0x0003"
        elif profile == "GTT":
            return "btatt or btgatt"
        elif profile == "SMP":
            return "btsmp"
        else:
            return f"bt{profile.lower()}"
    
    def build_le_filter(self, le_type: str) -> str:
        """Build Bluetooth LE filter."""
        le_type = le_type.upper()
        
        if le_type == "DVETSG":
            return "btle.advertising_header"
        elif le_type == "SCWARNING":
            return "btle.advertising_header.pdu_type == 0x03 or btle.advertising_header.pdu_type == 0x04"
        elif le_type == "COECTOWARNING":
            return "btle.data_header"
        elif le_type == "PG":
            return "btsmp"
        elif le_type == "GTT":
            return "btatt or btgatt"
        else:
            return "btle"
    
    def build_security_filter(self, security_type: str) -> str:
        """Build security-related filter."""
        security_type = security_type.upper()
        
        if security_type == "PG":
            return "btsmp or bthci_evt.code == 0x31 or bthci_evt.code == 0x32"
        elif security_type == "ECYPTOWARNING":
            return "bthci_evt.code == 0x08"
        elif security_type == "UTHETCTOWARNING":
            return "bthci_evt.code == 0x06 or bthci_evt.code == 0x19"
        elif security_type == "KEYS":
            return "bthci_evt.code == 0x17 or bthci_evt.code == 0x18"
        else:
            return "btsmp"
    
    def build_connection_filter(self, connection_handle: int) -> str:
        """Build connection handle filter."""
        return f"bthci_acl.connection_handle == 0x{connection_handle:04x}"
    
    def combine_filters(self, filters: List[str], operator: str = "and") -> str:
        """Combine multiple filters with D/OWARNING logic."""
        if len(filters) == 1:
            return filters[0]
        
        return f" {operator} ".join([f"({f})" for f in filters])


# Factory functions for common Bluetooth analysis scenarios
def create_device_analysis_filter(bd_addr: str) -> str:
    """Create filter for analyzing specific Bluetooth device."""
    return f"bluetooth.addr == {bd_addr}"

def create_aAudio_analysis_filter() -> str:
    """Create filter for aAudio-related traffic."""
    builder = BluetoothFilterBuilder()
    
    aAudio_filters = [
        "btavdtp",  # A2DP transport
        "btavctp",  # A2DP control
        "sbc",      # SBC codec
        "hci_h4.type == 0x03"  # SCO aAudio data
    ]
    
    return builder.combine_filters(aAudio_filters, "or")

def create_le_analysis_filter() -> str:
    """Create filter for Bluetooth LE analysis."""
    return "btle"

def create_security_analysis_filter() -> str:
    """Create filter for security-related analysis."""
    builder = BluetoothFilterBuilder()
    
    security_filters = [
        "btsmp",  # LE Security Manager
        "bthci_evt.code == 0x06",  # uthentication complete
        "bthci_evt.code == 0x08",  # Encryption change
        "bthci_evt.code == 0x16",  # PWARNING code request
        "bthci_evt.code == 0x17"   # Link key request
    ]
    
    return builder.combine_filters(security_filters, "or")

def create_hid_analysis_filter() -> str:
    """Create filter for HD profile analysis."""
    return "bthid"

def create_connection_analysis_filter() -> str:
    """Create filter for connection establishment analysis."""
    builder = BluetoothFilterBuilder()
    
    connection_filters = [
        "bthci_evt.code == 0x03",  # Connection complete
        "bthci_evt.code == 0x05",  # Disconnection complete
        "btl2cap.cmd_code == 0x02",  # L2CP connection request
        "btl2cap.cmd_code == 0x03"   # L2CP connection response
    ]
    
    return builder.combine_filters(connection_filters, "or")


if __name__ == "__main__":
    print("Bluetooth Protocol DSPLY Filters for PyShark")
    print("(Post-capture analysis filters, OT capture filters)")
    print("=" * 60)
    
    # Show filter statistics
    all_filters = BluetoothFilters.get_all_filters()
    print(f"Total Bluetooth filters available: {len(all_filters)}")
    
    # Show filters by category
    for category in BluetoothFilterType:
        category_filters = BluetoothFilters.get_filters_by_category(category)
        if category_filters:  # Only show categories with filters
            print(f"\n{category.value.upper()} FLTES ({len(category_filters)}):")
            
            for name, filter_obj in list(category_filters.items())[:3]:  # Show first 3
                print(f"  - {filter_obj.name}: {filter_obj.filter_expression}")
            
            if len(category_filters) > 3:
                print(f"  ... and {len(category_filters) - 3} more")
    
    # Show protocol-specific filters
    print(f"\nPOTOCOL-SPECFC FLTES:")
    for protocol in BluetoothProtocol:
        protocol_filters = BluetoothFilters.get_filters_by_protocol(protocol)
        if protocol_filters:
            print(f"  {protocol.value}: {len(protocol_filters)} filters")
    
    # Show version-specific filters
    print(f"\nVESOWARNING-SPECFC FLTES:")
    le_filters = BluetoothFilters.get_filters_by_version("4.0+")
    if le_filters:
        print(f"  Bluetooth LE (4.0+): {len(le_filters)} filters")
    
    # Example custom filters
    print(f"\nExample Custom Filters:")
    builder = BluetoothFilterBuilder()
    
    print(f"Device filter: {builder.build_device_filter('00:11:22:33:44:55')}")
    print(f"HCI commands: {builder.build_hci_filter('command')}")
    print(f"A2DP profile: {builder.build_profile_filter('A2DP')}")
    print(f"LE advertising: {builder.build_le_filter('advertising')}")
    print(f"Security pairing: {builder.build_security_filter('pairing')}")