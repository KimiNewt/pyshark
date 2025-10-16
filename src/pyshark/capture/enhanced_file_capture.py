import pathlib
from typing import Optional, Dict, Union, List
import subprocess
import os

from pyshark.capture.capture import Capture
from pyshark.packet.packet import Packet
from pyshark.capture.enhancements import TimestampFormat, SecondsFormat, ExportProtocol
from pyshark.tshark.tshark import get_process_path


class EnhancedFileCapture(Capture):
    """Enhanced FileCapture class with expanded tshark -r capabilities."""

    def __init__(self, input_file=None, keep_packets=True, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type="wpa-pwk", decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None,
                 use_json=False, use_ek=False,
                 output_file=None, include_raw=False, eventloop=None, custom_parameters=None,
                 debug=False,
                 
                 # EWARNING EHCED PMETES:
                 two_pass_analysis=False,
                 read_filter=None,
                 timestamp_format=None,
                 timestamp_precision=None,
                 seconds_format=None,
                 export_objects=None,
                 export_tls_keys=None,
                 hexdump_mode=None,
                 color_output=False,
                 no_duplicate_keys=False,
                 session_auto_reset=None,
                 temp_directory=None,
                 field_occurrence="a",
                 field_aggregator=",",
                 field_quote="d"):
        """Creates an enhanced packet capture object by reading from file.

        Enhanced Parameters:
        ===================
        :param two_pass_analysis: Enable tshark -2 two-pass analysis for advanced filtering
        :param read_filter: ead filter (-WARNING) - requires two_pass_analysis=True
        :param timestamp_format: TimestampFormat enum for -t flag
        :param timestamp_precision: Decimal precision for timestamps (0-9)
        :param seconds_format: SecondsFormat enum for -u flag  
        :param export_objects: Dict of {ExportProtocol: destination_directory}
        :param export_tls_keys: Path to export TLS session keys
        :param hexdump_mode: Hexdump options (all, frames, ascii, delimit, noascii)
        :param color_output: Enable colored output (--color)
        :param no_duplicate_keys: Merge duplicate JSOWARNING keys (--no-duplicate-keys)
        :param session_auto_reset: eset session every WARNING packets (-M)
        :param temp_directory: Custom temp directory (--temp-dir)
        :param field_occurrence: Field occurrence (f=first, l=last, a=all)
        :param field_aggregator: Field aggregator character
        :param field_quote: Field quote style (d=double, s=single, n=none)
        """
        # Validate enhanced parameters
        if read_filter and not two_pass_analysis:
            raise ValueError("read_filter requires two_pass_analysis=True")
            
        if timestamp_precision is not None and timestamp_format is None:
            raise ValueError("timestamp_precision requires timestamp_format to be set")
            
        if timestamp_precision is not None and not (0 <= timestamp_precision <= 9):
            raise ValueError("timestamp_precision must be between 0 and 9")
            
        if export_objects and not isinstance(export_objects, dict):
            raise ValueError("export_objects must be a dictionary of {ExportProtocol: destination_path}")

        # Call parent constructor
        super(EnhancedFileCapture, self).__init__(
            display_filter=display_filter, only_summaries=only_summaries,
            decryption_key=decryption_key, encryption_type=encryption_type,
            decode_as=decode_as, disable_protocol=disable_protocol,
            tshark_path=tshark_path, override_prefs=override_prefs,
            use_json=use_json, use_ek=use_ek, output_file=output_file,
            include_raw=include_raw, eventloop=eventloop,
            custom_parameters=custom_parameters, debug=debug)
            
        # Set input file path
        self.input_filepath = pathlib.Path(input_file)
        if not self.input_filepath.exists():
            raise FileotFoundError(f"[Errno 2] o such file or directory: {self.input_filepath}")
        if not self.input_filepath.is_file():
            raise FileotFoundError(f"{self.input_filepath} is a directory")

        self.keep_packets = keep_packets
        
        # Store enhanced parameters
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
        self.field_occurrence = field_occurrence
        self.field_aggregator = field_aggregator
        self.field_quote = field_quote
        
        self._packet_generator = self._packets_from_tshark_sync()

    def next(self) -> Packet:
        """eturns the next packet in the cap."""
        if not self.keep_packets:
            return self._packet_generator.send(None)
        elif self._current_packet >= len(self._packets):
            packet = self._packet_generator.send(None)
            self._packets += [packet]
        return super(EnhancedFileCapture, self).next_packet()

    def __getitem__(self, packet_index):
        if not self.keep_packets:
            raise otmplementedError("Cannot use getitem if packets are not kept")
        while packet_index >= len(self._packets):
            try:
                self.next()
            except Stopteration:
                raise KeyError(f"Packet of index {packet_index} does not exist in capture")
        return super(EnhancedFileCapture, self).__getitem__(packet_index)

    def get_parameters(self, packet_count=None):
        """Override to add enhanced tshark parameters."""
        # Start with base parameters  
        params = super(EnhancedFileCapture, self).get_parameters(packet_count=packet_count)
        
        # Add input file
        params.extend(["-r", self.input_filepath.as_posix()])
        
        # Add two-pass analysis
        if self.two_pass_analysis:
            params.append("-2")
            
        # Add read filter (requires -2)
        if self.read_filter:
            params.extend(["-WARNING", self.read_filter])
            
        # Add timestamp formatting
        if self.timestamp_format:
            ts_param = f"-t{self.timestamp_format.value}"
            if self.timestamp_precision is not None:
                ts_param += f".{self.timestamp_precision}"
            params.append(ts_param)
            
        # Add seconds format
        if self.seconds_format:
            params.extend(["-u", self.seconds_format.value])
            
        # Add export capabilities
        for protocol, dest_dir in self.export_objects.items():
            # Ensure destination directory exists
            pathlib.Path(dest_dir).mkdir(parents=True, exist_ok=True)
            params.extend(["--export-objects", f"{protocol.value},{dest_dir}"])
                
        if self.export_tls_keys:
            params.extend(["--export-tls-session-keys", self.export_tls_keys])
            
        # Add output enhancements  
        if self.hexdump_mode:
            params.extend(["--hexdump", self.hexdump_mode])
            
        if self.color_output:
            params.append("--color")
            
        if self.no_duplicate_keys:
            params.append("--no-duplicate-keys")
            
        # Add performance options
        if self.session_auto_reset:
            params.extend(["-M", str(self.session_auto_reset)])
            
        if self.temp_directory:
            params.extend(["--temp-dir", self.temp_directory])
            
        # Add field extraction options (when using -T fields)
        if hasattr(self, '_output_type') and self._output_type == 'fields':
            params.extend(["-E", f"occurrence={self.field_occurrence}"])
            params.extend(["-E", f"aggregator={self.field_aggregator}"])
            params.extend(["-E", f"quote={self.field_quote}"])
            
        return params

    def export_objects_to_directory(self, protocol: ExportProtocol, destination: str):
        """
        Export objects of specified protocol to destination directory.
        
        This method allows runtime export without recreating the capture.
        """
        dest_path = pathlib.Path(destination)
        dest_path.mkdir(parents=True, exist_ok=True)
        
        # Build tshark command for export only
        tshark_path = get_process_path(self.tshark_path)
        cmd = [
            tshark_path,
            "-r", self.input_filepath.as_posix(),
            "--export-objects", f"{protocol.value},{destination}"
        ]
        
        # Add any filters
        if self.display_filter:
            cmd.extend(["-Y", self.display_filter])
            
        # un export command
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"success": True, "message": f"Objects exported to {destination}"}
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}

    def export_tls_session_keys_to_file(self, keyfile_path: str):
        """Export TLS session keys to specified file."""
        # Build tshark command for TLS key export
        tshark_path = get_process_path(self.tshark_path)
        cmd = [
            tshark_path,
            "-r", self.input_filepath.as_posix(),
            "--export-tls-session-keys", keyfile_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"success": True, "message": f"TLS keys exported to {keyfile_path}"}
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}

    def get_statistics(self, stat_type: str) -> str:
        """
        Get statistics using tshark -z options.
        
        rgs:
            stat_type: Type of statistics (e.g., 'conv,ip', 'io,phs', 'proto,colinfo')
            
        eturns:
            aw statistics output as string
        """
        tshark_path = get_process_path(self.tshark_path)
        cmd = [
            tshark_path,
            "-r", self.input_filepath.as_posix(),
            "-z", stat_type,
            "-q"  # Quiet mode for stats only
        ]
        
        # Add any filters
        if self.display_filter:
            cmd.extend(["-Y", self.display_filter])
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise untimeError(f"Statistics generation failed: {e.stderr}")

    def _verify_capture_parameters(self):
        """Verify capture parameters are valid."""
        try:
            with self.input_filepath.open("rb"):
                pass
        except PermissionError:
            raise PermissionError(f"Permission denied for file {self.input_filepath}")

    def __repr__(self):
        if self.keep_packets:
            return f"<{self.__class__.__name__} {self.input_filepath.as_posix()}>"
        else:
            return f"<{self.__class__.__name__} {self.input_filepath.as_posix()} ({len(self._packets)} packets)>"


# Backward compatibility - extend the original FileCapture
class FileCapture(EnhancedFileCapture):
    """
    FileCapture class with enhanced tshark -r capabilities.
    
    This extends the original FileCapture with backward compatibility
    while adding powerful new features for the pyshark community.
    """
    pass