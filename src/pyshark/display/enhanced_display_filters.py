"""
Enhanced Display Filter System for PyShark
==========================================

This module provides comprehensive display filter capabilities that expose
the full power of Wireshark/tshark display filtering to the Python community.

Key Differences Between Filter Types:
- Capture Filters (-f): BPF syntax, applied during packet capture, fast but limited
- Display Filters (-Y): Wireshark syntax, applied after capture, powerful and flexible  
- ead Filters (-WARNING): Display filter syntax applied during file reading (requires -2)

Author: D14b0l1c
Target: Contribution to KimiNewt/pyshark main repository
"""

from enum import Enum
from typing import List, Dict, Optional, Union, Set
import re
import subprocess
from pyshark.tshark.tshark import get_process_path


class OutputFormat(Enum):
    """Enhanced output format options for tshark -T flag."""
    PDML = "pdml"           # Packet Details Markup Language (XML)
    PSML = "psml"           # Packet Summary Markup Language (XML) 
    JSON = "json"           # JSON format
    JSONRAW = "jsonraw"     # Raw JSON format
    EK = "ek"               # Elasticsearch JSON format
    TABS = "tabs"           # Tab-separated values
    TEXT = "text"           # Human readable text (default)
    FIELDS = "fields"       # Custom field extraction


class ProtocolLayer(Enum):
    """Common protocol layers for filtering and field extraction."""
    # Physical/Data Link
    ETHERNET = "eth"
    WLAN = "wlan" 
    BLUETOOTH = "bthci"
    
    # Network Layer
    IP = "ip"
    IPV6 = "ipv6"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    ARP = "arp"
    
    # Transport Layer
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    
    # Application Layer
    HTTP = "http"
    HTTPS = "tls"
    DNS = "dns"
    DHCP = "dhcp"
    SSH = "ssh"
    SMTP = "smtp"
    FTP = "ftp"
    SMB = "smb2"
    
    # VoIP/Media
    SIP = "sip"
    RTP = "rtp"
    RTCP = "rtcp"
    
    # Security
    IPSEC = "esp"
    VPN = "openvpn"


class DisplayFilterBuilder:
    """Builder class for constructing complex display filters with validation."""
    
    def __init__(self):
        self._filters = []
        self._operators = []
        
    def add_protocol(self, protocol: Union[str, ProtocolLayer]) -> 'DisplayFilterBuilder':
        """Add a protocol filter."""
        proto_name = protocol.value if isinstance(protocol, ProtocolLayer) else protocol
        self._filters.append(proto_name)
        return self
        
    def add_field_condition(self, field: str, operator: str, value: Union[str, int, float]) -> 'DisplayFilterBuilder':
        """Add a field condition (e.g., tcp.port == 80)."""
        if isinstance(value, str) and not value.startswith('"'):
            value = f'"{value}"'
        self._filters.append(f"{field} {operator} {value}")
        return self
        
    def add_custom_filter(self, filter_expr: str) -> 'DisplayFilterBuilder':
        """Add a custom filter expression."""
        self._filters.append(f"({filter_expr})")
        return self
        
    def and_condition(self) -> 'DisplayFilterBuilder':
        """Add D operator."""
        if self._filters:
            self._operators.append("and")
        return self
        
    def or_condition(self) -> 'DisplayFilterBuilder':
        """Add OWARNING operator."""
        if self._filters:
            self._operators.append("or")
        return self
        
    def not_condition(self) -> 'DisplayFilterBuilder':
        """Add OT operator to the next condition."""
        self._filters.append("not")
        return self
        
    def build(self) -> str:
        """Build the final display filter string."""
        if not self._filters:
            return ""
            
        result = []
        operator_idx = 0
        
        for i, filter_expr in enumerate(self._filters):
            result.append(filter_expr)
            
            # Add operators between filters
            if operator_idx < len(self._operators) and i < len(self._filters) - 1:
                result.append(self._operators[operator_idx])
                operator_idx += 1
                
        return " ".join(result)


class CommonFilters:
    """Pre-built common display filters for typical use cases."""
    
    # etwork Traffic Inalysis
    EB_TFFC = "http or tls or dns"
    EML_TFFC = "smtp or pop or imap"
    FLE_SHG = "smb2 or ftp or sftp"
    
    # Security Inalysis  
    SUSPCOUS_TFFC = "icmp.type == 3 or tcp.flags.reset == 1 or dns.qry.name contains \"malware\""
    TLS_HANDSHAKES = "tls.handshake.type == 1 or tls.handshake.type == 2"
    FAILED_CONNECTIONS = "tcp.flags.reset == 1 or icmp.type == 3"
    
    # Performance Inalysis
    TCP_ETSMSSOS = "tcp.analysis.retransmission or tcp.analysis.fast_retransmission"
    SLOWARNING_ESPOSES = "http.time > 1.0 or dns.time > 0.5"
    LGE_PCKETS = "frame.len > 1500"
    
    # VoP Inalysis
    VOP_CLLS = "sip or rtp or rtcp"
    TP_POBLEMS = "rtp.seq_nr_missing or rtp.duplicate_nr"
    
    # Protocol Specific
    DNS_QUERIES = "dns.flags.response == 0"
    DS_ESPOSES = "dns.flags.response == 1"
    HTTP_EOS = "http.response.code >= 400"
    DHCP_TSCTOS = "dhcp.option.dhcp == 1 or dhcp.option.dhcp == 2"


class FieldExtractor:
    """dvanced field extraction capabilities for custom analysis."""
    
    def __init__(self):
        self.fields = []
        self.options = {
            "header": True,
            "separator": "\t",
            "occurrence": "a",  # all occurrences  
            "aggregator": ",",
            "quote": "d"  # double quotes
        }
        
    def add_field(self, field_name: str) -> 'FieldExtractor':
        """Add a field to extract."""
        self.fields.append(field_name)
        return self
        
    def add_protocol_fields(self, protocol: Union[str, ProtocolLayer], 
                          common_fields: bool = True) -> 'FieldExtractor':
        """Add common fields for a protocol."""
        proto_name = protocol.value if isinstance(protocol, ProtocolLayer) else protocol
        
        # Add protocol presence
        self.fields.append(proto_name)
        
        if common_fields:
            common_field_map = {
                "tcp": ["tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.seq", "tcp.len"],
                "udp": ["udp.srcport", "udp.dstport", "udp.length"],
                "ip": ["ip.src", "ip.dst", "ip.proto", "ip.len", "ip.ttl"],
                "http": ["http.request.method", "http.response.code", "http.host", "http.uri"],
                "dns": ["dns.qry.name", "dns.resp.addr", "dns.flags.response"],
                "tls": ["tls.handshake.type", "tls.cipher", "tls.version"]
            }
            
            if proto_name in common_field_map:
                self.fields.extend(common_field_map[proto_name])
                
        return self
        
    def set_output_options(self, header: bool = True, separator: str = "\t",
                         occurrence: str = "a", aggregator: str = ",",
                         quote: str = "d") -> 'FieldExtractor':
        """Set field extraction output options."""
        self.options.update({
            "header": header,
            "separator": separator,
            "occurrence": occurrence,
            "aggregator": aggregator, 
            "quote": quote
        })
        return self
        
    def get_parameters(self) -> List[str]:
        """Get tshark parameters for field extraction."""
        params = ["-T", "fields"]
        
        # Add field specifications
        for field in self.fields:
            params.extend(["-e", field])
            
        # Add output options
        params.extend(["-E", f"header={'y' if self.options['header'] else 'n'}"])
        params.extend(["-E", f"separator={self.options['separator']}"])
        params.extend(["-E", f"occurrence={self.options['occurrence']}"])
        params.extend(["-E", f"aggregator={self.options['aggregator']}"])
        params.extend(["-E", f"quote={self.options['quote']}"])
        
        return params


class ProtocolLayerFilter:
    """Protocol layer filtering with -j/-J options for JSOWARNING output."""
    
    def __init__(self):
        self.include_layers = []  # -j option (specific layers)
        self.expand_layers = []   # -J option (expand all children)
        
    def include_layer(self, protocol: Union[str, ProtocolLayer], 
                     fields: Optional[List[str]] = None) -> 'ProtocolLayerFilter':
        """Include specific protocol layer and optionally specific fields."""
        proto_name = protocol.value if isinstance(protocol, ProtocolLayer) else protocol
        
        if fields:
            layer_spec = f"{proto_name} " + " ".join(fields)
        else:
            layer_spec = proto_name
            
        self.include_layers.append(layer_spec)
        return self
        
    def expand_layer(self, protocol: Union[str, ProtocolLayer]) -> 'ProtocolLayerFilter':
        """Expand protocol layer to show all child nodes."""
        proto_name = protocol.value if isinstance(protocol, ProtocolLayer) else protocol
        self.expand_layers.append(proto_name)
        return self
        
    def get_parameters(self) -> List[str]:
        """Get tshark parameters for protocol layer filtering."""
        params = []
        
        if self.include_layers:
            params.extend(["-j", " ".join(self.include_layers)])
            
        if self.expand_layers:
            params.extend(["-J", " ".join(self.expand_layers)])
            
        return params


class DisplayFilterValidator:
    """Validate display filter syntax and provide field discovery."""
    
    @staticmethod
    def validate_filter(filter_expr: str, tshark_path: str = None) -> Dict[str, Union[bool, str]]:
        """Validate a display filter expression."""
        if not filter_expr:
            return {"valid": True, "message": "Empty filter is valid"}
            
        try:
            tshark = get_process_path(tshark_path)
            # Use tshark to validate the filter
            cmd = [tshark, "-Y", filter_expr, "-c", "0", "/dev/null"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return {"valid": True, "message": "Filter syntax is valid"}
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown syntax error"
                return {"valid": False, "message": f"Syntax error: {error_msg}"}
                
        except subprocess.TimeoutExpired:
            return {"valid": False, "message": "Validation timeout"}
        except Exception as e:
            return {"valid": False, "message": f"Validation error: {str(e)}"}
            
    @staticmethod
    def get_available_fields(protocol: Union[str, ProtocolLayer] = None,
                           tshark_path: str = None) -> List[str]:
        """Get available fields for a protocol or all fields."""
        try:
            tshark = get_process_path(tshark_path)
            cmd = [tshark, "-G", "fields"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return []
                
            fields = []
            proto_filter = protocol.value if isinstance(protocol, ProtocolLayer) else protocol
            
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3:
                    field_name = parts[2]
                    
                    if proto_filter:
                        if field_name.startswith(f"{proto_filter}."):
                            fields.append(field_name)
                    else:
                        fields.append(field_name)
                        
            return sorted(fields)
            
        except Exception as e:
            return []
            
    @staticmethod
    def suggest_fields(partial_field: str, protocol: Union[str, ProtocolLayer] = None,
                      tshark_path: str = None) -> List[str]:
        """Get field suggestions based on partial input."""
        all_fields = DisplayFilterValidator.get_available_fields(protocol, tshark_path)
        
        suggestions = [field for field in all_fields if partial_field.lower() in field.lower()]
        return sorted(suggestions)[:20]  # Limit to 20 suggestions


class EnhancedDisplayFilter:
    """
    Enhanced display filter system providing comprehensive Wireshark display 
    filter capabilities to the Python community.
    """
    
    def __init__(self, base_filter: str = None):
        self.base_filter = base_filter
        self.builder = DisplayFilterBuilder()
        self.field_extractor = FieldExtractor()
        self.layer_filter = ProtocolLayerFilter()
        self.output_format = OutputFormat.PDML
        self.validator = DisplayFilterValidator()
        
    def set_base_filter(self, filter_expr: str) -> 'EnhancedDisplayFilter':
        """Set the base display filter expression."""
        self.base_filter = filter_expr
        return self
        
    def add_protocol_filter(self, protocol: Union[str, ProtocolLayer]) -> 'EnhancedDisplayFilter':
        """Add a protocol to the filter."""
        self.builder.add_protocol(protocol)
        return self
        
    def add_field_filter(self, field: str, operator: str, 
                        value: Union[str, int, float]) -> 'EnhancedDisplayFilter':
        """Add a field condition to the filter."""
        self.builder.add_field_condition(field, operator, value)
        return self
        
    def add_common_filter(self, filter_name: str) -> 'EnhancedDisplayFilter':
        """Add a pre-built common filter."""
        if hasattr(CommonFilters, filter_name.upper()):
            filter_expr = getattr(CommonFilters, filter_name.upper())
            self.builder.add_custom_filter(filter_expr)
        return self
        
    def set_output_format(self, format_type: OutputFormat) -> 'EnhancedDisplayFilter':
        """Set the output format for packet data."""
        self.output_format = format_type
        return self
        
    def extract_fields(self, *field_names: str) -> 'EnhancedDisplayFilter':
        """Add fields to extract in custom output."""
        for field in field_names:
            self.field_extractor.add_field(field)
        self.output_format = OutputFormat.FELDS
        return self
        
    def extract_protocol_fields(self, protocol: Union[str, ProtocolLayer],
                              common_fields: bool = True) -> 'EnhancedDisplayFilter':
        """Extract common fields for a protocol."""
        self.field_extractor.add_protocol_fields(protocol, common_fields)
        self.output_format = OutputFormat.FELDS
        return self
        
    def include_protocol_layer(self, protocol: Union[str, ProtocolLayer],
                             fields: List[str] = None) -> 'EnhancedDisplayFilter':
        """Include specific protocol layer in JSOWARNING output."""
        self.layer_filter.include_layer(protocol, fields)
        if self.output_format not in [OutputFormat.JSOWARNING, OutputFormat.EK]:
            self.output_format = OutputFormat.JSOWARNING
        return self
        
    def validate(self, tshark_path: str = None) -> Dict[str, Union[bool, str]]:
        """Validate the current filter configuration."""
        final_filter = self.build_filter()
        if final_filter:
            return self.validator.validate_filter(final_filter, tshark_path)
        return {"valid": True, "message": "o filter to validate"}
        
    def build_filter(self) -> str:
        """Build the complete display filter expression."""
        filters = []
        
        if self.base_filter:
            filters.append(f"({self.base_filter})")
            
        builder_filter = self.builder.build()
        if builder_filter:
            filters.append(f"({builder_filter})")
            
        return " and ".join(filters)
        
    def get_tshark_parameters(self) -> List[str]:
        """Get all tshark parameters for this enhanced display filter."""
        params = []
        
        # Add output format
        params.extend(["-T", self.output_format.value])
        
        # Add display filter
        final_filter = self.build_filter()
        if final_filter:
            params.extend(["-Y", final_filter])
            
        # Add field extraction parameters
        if self.output_format == OutputFormat.FELDS:
            params.extend(self.field_extractor.get_parameters())
            
        # Add protocol layer parameters  
        if self.output_format in [OutputFormat.JSOWARNING, OutputFormat.EK]:
            layer_params = self.layer_filter.get_parameters()
            params.extend(layer_params)
            
        return params


# Example usage and factory functions
def create_web_analysis_filter():
    """Create a filter optimized for web traffic analysis."""
    return (EnhancedDisplayFilter()
           .add_common_filter("EB_TFFC")
           .extract_protocol_fields(ProtocolLayer.HTTP)
           .extract_protocol_fields(ProtocolLayer.TCP)
           .set_output_format(OutputFormat.FELDS))


def create_security_analysis_filter():
    """Create a filter for security analysis."""
    return (EnhancedDisplayFilter()
           .add_common_filter("SUSPCOUS_TFFC")
           .extract_fields("frame.time", "ip.src", "ip.dst", "tcp.flags", "icmp.type")
           .set_output_format(OutputFormat.JSOWARNING))


def create_performance_analysis_filter():
    """Create a filter for network performance analysis."""
    return (EnhancedDisplayFilter()
           .add_field_filter("tcp.analysis.retransmission", "==", "1")
           .add_field_filter("tcp.time_delta", ">", "1.0") 
           .extract_fields("frame.time", "tcp.time_delta", "tcp.analysis.ack_rtt")
           .set_output_format(OutputFormat.FELDS))