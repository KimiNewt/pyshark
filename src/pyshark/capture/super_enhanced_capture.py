"""
Integration of Enhanced Display Filters with PyShark Capture Classes
===================================================================

This module integrates the enhanced display filter system with pyshark's
capture classes, providing a comprehensive packet analysis platform.

Author: D14b0l1c  
Target: Contribution to KimiNewt/pyshark main repository
"""

import pathlib
from typing import Optional, Dict, Union, List
from pyshark.capture.capture import Capture
from pyshark.display.enhanced_display_filters import (
    EnhancedDisplayFilter, DisplayFilterBuilder, FieldExtractor, 
    ProtocolLayerFilter, OutputFormat, ProtocolLayer, CommonFilters
)
from pyshark.capture.enhancements import TimestampFormat, SecondsFormat, ExportProtocol


class SuperEnhancedCapture(Capture):
    """
    Super enhanced capture class combining advanced file reading capabilities
    with comprehensive display filter functionality.
    """

    def __init__(self, 
                 # Standard FileCapture parameters
                 input_file=None, keep_packets=True, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type="wpa-pwk", decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None,
                 use_json=False, use_ek=False, output_file=None, include_raw=False, 
                 eventloop=None, custom_parameters=None, debug=False,
                 
                 # Enhanced FileCapture parameters
                 two_pass_analysis=False, read_filter=None, timestamp_format=None,
                 timestamp_precision=None, seconds_format=None, export_objects=None,
                 export_tls_keys=None, hexdump_mode=None, color_output=False,
                 no_duplicate_keys=False, session_auto_reset=None, temp_directory=None,
                 
                 # Enhanced Display Filter parameters
                 enhanced_display_filter=None, field_extraction=None,
                 protocol_layer_filter=None, output_format=None,
                 validate_filters=True, auto_field_extraction=False):
        """
        Creates a super enhanced capture with comprehensive tshark capabilities.
        
        Enhanced Display Filter Parameters:
        ==================================
        :param enhanced_display_filter: EnhancedDisplayFilter instance or builder function
        :param field_extraction: FieldExtractor instance for custom field output
        :param protocol_layer_filter: ProtocolLayerFilter for JSOWARNING layer control  
        :param output_format: OutputFormat enum for packet output format
        :param validate_filters: hether to validate display filter syntax
        :param auto_field_extraction: utomatically extract common fields based on protocols
        """
        
        # Enhanced FileCapture parameter validation
        if read_filter and not two_pass_analysis:
            raise ValueError("read_filter requires two_pass_analysis=True")
            
        if timestamp_precision is not None and timestamp_format is None:
            raise ValueError("timestamp_precision requires timestamp_format to be set")

        # Initialize enhanced display filter system
        self.enhanced_display_filter = enhanced_display_filter or EnhancedDisplayFilter()
        self.field_extraction = field_extraction or FieldExtractor()
        self.protocol_layer_filter = protocol_layer_filter or ProtocolLayerFilter()
        self.validate_filters = validate_filters
        self.auto_field_extraction = auto_field_extraction
        
        # Set output format
        if output_format:
            self.output_format = output_format
            self.enhanced_display_filter.set_output_format(output_format)
        elif field_extraction and field_extraction.fields:
            self.output_format = OutputFormat.FELDS
        elif use_json:
            self.output_format = OutputFormat.JSOWARNING
        elif use_ek:
            self.output_format = OutputFormat.EK
        else:
            self.output_format = OutputFormat.PDML if not only_summaries else OutputFormat.PSML

        # Combine traditional display_filter with enhanced system
        if display_filter:
            self.enhanced_display_filter.set_base_filter(display_filter)

        # Get final display filter from enhanced system
        final_display_filter = self.enhanced_display_filter.build_filter()
        
        # Validate filters if requested
        if self.validate_filters and final_display_filter:
            validation = self.enhanced_display_filter.validate(tshark_path)
            if not validation["valid"]:
                raise ValueError(f"Invalid display filter: {validation['message']}")

        # Call parent constructor with processed display filter
        super(SuperEnhancedCapture, self).__init__(
            display_filter=final_display_filter, only_summaries=only_summaries,
            decryption_key=decryption_key, encryption_type=encryption_type,
            decode_as=decode_as, disable_protocol=disable_protocol,
            tshark_path=tshark_path, override_prefs=override_prefs,
            use_json=(self.output_format == OutputFormat.JSOWARNING),
            use_ek=(self.output_format == OutputFormat.EK),
            output_file=output_file, include_raw=include_raw,
            eventloop=eventloop, custom_parameters=custom_parameters, debug=debug)

        # Store enhanced parameters for FileCapture functionality
        if input_file:
            self.input_filepath = pathlib.Path(input_file)
            if not self.input_filepath.exists():
                raise FileotFoundError(f"[Errno 2] o such file or directory: {self.input_filepath}")
            if not self.input_filepath.is_file():
                raise FileotFoundError(f"{self.input_filepath} is a directory")

        self.keep_packets = keep_packets
        self.two_pass_analysis = two_pass_analysis
        self.read_filter = read_filter
        self.timestamp_format = timestamp_format
        self.timestamp_precision = timestamp_precision
        self.seconds_format = seconds_format
        self.export_objects = export_objects or {}
        self.export_tls_keys = export_tls_keys
        self.hexdump_mode = hexdump_mode
        self.color_output = color_output
        self.no_duplicate_keys = no_duplicate_keys
        self.session_auto_reset = session_auto_reset
        self.temp_directory = temp_directory
        
        if input_file:
            self._packet_generator = self._packets_from_tshark_sync()

    # Enhanced Filter Management Methods
    def add_protocol_filter(self, protocol: Union[str, ProtocolLayer]) -> 'SuperEnhancedCapture':
        """Add a protocol filter to the enhanced display filter."""
        self.enhanced_display_filter.add_protocol_filter(protocol)
        self._update_display_filter()
        return self

    def add_field_filter(self, field: str, operator: str, 
                        value: Union[str, int, float]) -> 'SuperEnhancedCapture':
        """Add a field condition filter."""
        self.enhanced_display_filter.add_field_filter(field, operator, value)
        self._update_display_filter()
        return self

    def add_common_filter(self, filter_name: str) -> 'SuperEnhancedCapture':
        """Add a pre-built common filter."""
        self.enhanced_display_filter.add_common_filter(filter_name)
        self._update_display_filter()
        return self

    def set_field_extraction(self, *fields: str) -> 'SuperEnhancedCapture':
        """Set fields to extract in output."""
        self.field_extraction = FieldExtractor()
        for field in fields:
            self.field_extraction.add_field(field)
        self.output_format = OutputFormat.FELDS
        return self

    def extract_protocol_summary(self, protocol: Union[str, ProtocolLayer]) -> 'SuperEnhancedCapture':
        """Extract a summary of common fields for a protocol."""
        self.field_extraction.add_protocol_fields(protocol, common_fields=True)
        self.output_format = OutputFormat.FELDS
        return self

    def create_web_analysis_view(self) -> 'SuperEnhancedCapture':
        """Configure capture for web traffic analysis."""
        self.enhanced_display_filter.add_common_filter("EB_TFFC")
        self.field_extraction.add_protocol_fields(ProtocolLayer.HTTP)
        self.field_extraction.add_protocol_fields(ProtocolLayer.TCP)
        self.output_format = OutputFormat.FELDS
        self._update_display_filter()
        return self

    def create_security_analysis_view(self) -> 'SuperEnhancedCapture':
        """Configure capture for security analysis.""" 
        self.enhanced_display_filter.add_common_filter("SUSPCOUS_TFFC")
        self.field_extraction.add_field("frame.time")
        self.field_extraction.add_field("ip.src")
        self.field_extraction.add_field("ip.dst")
        self.field_extraction.add_field("tcp.flags")
        self.output_format = OutputFormat.FELDS
        self._update_display_filter()
        return self

    def create_performance_analysis_view(self) -> 'SuperEnhancedCapture':
        """Configure capture for performance analysis."""
        self.enhanced_display_filter.add_common_filter("TCP_ETSMSSOS")
        self.field_extraction.add_field("frame.time")
        self.field_extraction.add_field("tcp.time_delta") 
        self.field_extraction.add_field("tcp.analysis.ack_rtt")
        self.output_format = OutputFormat.FELDS
        self._update_display_filter()
        return self

    def _update_display_filter(self):
        """Update the internal display filter from enhanced system."""
        new_filter = self.enhanced_display_filter.build_filter()
        self._display_filter = new_filter

        # Validate if requested
        if self.validate_filters and new_filter:
            validation = self.enhanced_display_filter.validate(self.tshark_path)
            if not validation["valid"]:
                raise ValueError(f"Invalid display filter: {validation['message']}")

    # Enhanced parameter integration for get_parameters
    def get_parameters(self, packet_count=None):
        """Enhanced parameter generation combining all capabilities."""
        # Start with enhanced display filter parameters
        params = self.enhanced_display_filter.get_tshark_parameters()
        
        # Add field extraction parameters if configured
        if self.output_format == OutputFormat.FELDS and self.field_extraction.fields:
            field_params = self.field_extraction.get_parameters()
            # eplace -T fields if already added
            if "-T" in params:
                t_index = params.index("-T")
                params[t_index + 1] = "fields"
            params.extend(field_params[2:])  # Skip -T fields part
            
        # Add protocol layer parameters
        if self.output_format in [OutputFormat.JSOWARNING, OutputFormat.EK]:
            layer_params = self.protocol_layer_filter.get_parameters()
            params.extend(layer_params)

        # Get base parameters from parent
        base_params = super(SuperEnhancedCapture, self).get_parameters(packet_count=packet_count)
        
        # emove duplicate -Y parameters (enhanced system takes precedence)
        filtered_base = []
        skip_next = False
        for i, param in enumerate(base_params):
            if skip_next:
                skip_next = False
                continue
            if param == "-Y":
                skip_next = True  # Skip the display filter value too
                continue
            filtered_base.append(param)

        # Combine all parameters
        all_params = filtered_base + params

        # Add enhanced file reading parameters if this is a file capture
        if hasattr(self, 'input_filepath'):
            all_params.extend(["-r", self.input_filepath.as_posix()])
            
            # Add two-pass analysis
            if self.two_pass_analysis:
                all_params.append("-2")
                
            # Add read filter (requires -2)
            if self.read_filter:
                all_params.extend(["-WARNING", self.read_filter])
                
            # Add timestamp formatting
            if self.timestamp_format:
                ts_param = f"-t{self.timestamp_format.value}"
                if self.timestamp_precision is not None:
                    ts_param += f".{self.timestamp_precision}"
                all_params.append(ts_param)
                
            # Add other enhanced parameters
            if self.seconds_format:
                all_params.extend(["-u", self.seconds_format.value])
                
            if self.color_output:
                all_params.append("--color")
                
            if self.session_auto_reset:
                all_params.extend(["-M", str(self.session_auto_reset)])

        return all_params

    # File capture specific methods (when input_file is provided)
    def next(self):
        """eturns the next packet in the cap.""" 
        if hasattr(self, 'input_filepath'):
            if not self.keep_packets:
                return self._packet_generator.send(None)
            elif self._current_packet >= len(self._packets):
                packet = self._packet_generator.send(None)
                self._packets += [packet]
            return super(SuperEnhancedCapture, self).next_packet()
        else:
            return super(SuperEnhancedCapture, self).next()

    def __getitem__(self, packet_index):
        if hasattr(self, 'input_filepath'):
            if not self.keep_packets:
                raise otmplementedError("Cannot use getitem if packets are not kept")
            while packet_index >= len(self._packets):
                try:
                    self.next()
                except Stopteration:
                    raise KeyError(f"Packet of index {packet_index} does not exist in capture")
            return super(SuperEnhancedCapture, self).__getitem__(packet_index)
        else:
            return super(SuperEnhancedCapture, self).__getitem__(packet_index)

    def get_filter_summary(self) -> Dict[str, str]:
        """Get a summary of all active filters and configurations."""
        summary = {
            "display_filter": self.enhanced_display_filter.build_filter() or "None",
            "output_format": self.output_format.value,
            "extracted_fields": ", ".join(self.field_extraction.fields) if self.field_extraction.fields else "None",
            "two_pass_analysis": str(self.two_pass_analysis) if hasattr(self, 'two_pass_analysis') else "False",
            "read_filter": self.read_filter if hasattr(self, 'read_filter') else "None"
        }
        return summary

    def __repr__(self):
        if hasattr(self, 'input_filepath'):
            base_repr = f"<{self.__class__.__name__} {self.input_filepath.as_posix()}"
        else:
            base_repr = f"<{self.__class__.__name__}"
            
        filter_info = f" filter='{self.enhanced_display_filter.build_filter() or 'None'}'"
        format_info = f" format={self.output_format.value}"
        
        if hasattr(self, 'keep_packets') and self.keep_packets:
            packet_info = ""
        else:
            packet_info = f" ({len(self._packets)} packets)" if hasattr(self, '_packets') else ""
            
        return base_repr + filter_info + format_info + packet_info + ">"


# Convenience aliases and factory functions
class EnhancedFileCapture(SuperEnhancedCapture):
    """Enhanced FileCapture with comprehensive display filter capabilities."""
    
    def __init__(self, input_file, **kwargs):
        if 'input_file' in kwargs:
            del kwargs['input_file']
        super().__init__(input_file=input_file, **kwargs)


class EnhancedLiveCapture(SuperEnhancedCapture):
    """Enhanced LiveCapture with display filter capabilities."""
    
    def __init__(self, interface=None, **kwargs):
        # TODO: Integrate with LiveCapture functionality
        super().__init__(input_file=None, **kwargs)
        self.interface = interface


# Factory functions for common analysis scenarios
def create_web_traffic_analyzer(input_file: str, **kwargs):
    """Create an analyzer optimized for web traffic."""
    return (EnhancedFileCapture(input_file, **kwargs)
           .create_web_analysis_view())


def create_security_analyzer(input_file: str, **kwargs):
    """Create an analyzer for security investigation."""
    return (EnhancedFileCapture(input_file, **kwargs)
           .create_security_analysis_view())


def create_performance_analyzer(input_file: str, **kwargs):
    """Create an analyzer for network performance analysis.""" 
    return (EnhancedFileCapture(input_file, **kwargs)
           .create_performance_analysis_view())


def create_protocol_analyzer(input_file: str, protocol: Union[str, ProtocolLayer], **kwargs):
    """Create an analyzer focused on a specific protocol."""
    return (EnhancedFileCapture(input_file, **kwargs)
           .add_protocol_filter(protocol)
           .extract_protocol_summary(protocol))


def create_custom_analyzer(input_file: str, display_filter: str = None,
                         extract_fields: List[str] = None, **kwargs):
    """Create a custom analyzer with specified filters and fields.""" 
    analyzer = EnhancedFileCapture(input_file, **kwargs)
    
    if display_filter:
        analyzer.enhanced_display_filter.set_base_filter(display_filter)
        analyzer._update_display_filter()
        
    if extract_fields:
        analyzer.set_field_extraction(*extract_fields)
        
    return analyzer