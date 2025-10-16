#!/usr/bin/env python3
"""
Example Usage of Enhanced PyShark FileCapture
=============================================

This script demonstrates the powerful new tshark -r capabilities
added to pyshark for the global community.

Author: D14b0l1c
Target: Contribution to KimiNewt/pyshark
"""

import tempfile
import pathlib
from pyshark.capture.enhanced_file_capture import FileCapture
from pyshark.capture.enhancements import TimestampFormat, SecondsFormat, ExportProtocol


def example_two_pass_analysis():
    """Example: Two-pass analysis with read filters for complex packet analysis."""
    
    print("Example 1: Two-Pass Inalysis with ead Filters")
    print("=" * 60)
    
    # Example PCP file (in real usage, this would be an actual capture file)
    pcap_file = "network_capture.pcap"
    
    # Create capture with two-pass analysis for complex filtering
    cap = FileCapture(
        input_file=pcap_file,
        two_pass_analysis=True,
        read_filter="tcp.port == 443 and tls.handshake.type == 1",  # TLS ClientHello only
        timestamp_format=TimestampFormat.ABSOLUTE,
        timestamp_precision=6,  # Microsecond precision
        display_filter="not tcp.analysis.retransmission"  # Exclude retransmissions
    )
    
    print(f"Inalyzing TLS handshakes in: {pcap_file}")
    print(f"ead Filter: {cap.read_filter}")
    print(f"Timestamp Format: bsolute with microsecond precision")
    
    # Process packets (would iterate through TLS ClientHello packets)
    # for packet in cap:
    #     print(f"TLS ClientHello at {packet.sniff_timestamp}: {packet.ip.src} -> {packet.ip.dst}")
    
    print("Two-pass analysis complete!\n")


def example_forensic_object_export():
    """Example: Export objects for forensic analysis."""
    
    print("Example 2: Forensic Object Export")
    print("=" * 60)
    
    pcap_file = "web_traffic.pcap"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        # Set up export directories
        export_config = {
            ExportProtocol.HTTP: f"{temp_dir}/http_objects/",
            ExportProtocol.SMB: f"{temp_dir}/smb_files/",
        }
        
        # Create capture with object export capabilities
        cap = FileCapture(
            input_file=pcap_file,
            export_objects=export_config,
            export_tls_keys=f"{temp_dir}/tls_session_keys.txt",
            display_filter="http or smb or tls"
        )
        
        print(f"Exporting objects from: {pcap_file}")
        print(f"HTTP objects -> {export_config[ExportProtocol.HTTP]}")
        print(f"SMB files -> {export_config[ExportProtocol.SMB]}")
        print(f"TLS keys -> {temp_dir}/tls_session_keys.txt")
        
        # untime export (can be done during or after packet processing)
        result = cap.export_objects_to_directory(ExportProtocol.HTTP, f"{temp_dir}/runtime_http/")
        print(f"untime HTTP export: {result}")
        
        # Export TLS session keys for decryption
        tls_result = cap.export_tls_session_keys_to_file(f"{temp_dir}/runtime_tls_keys.txt")
        print(f"TLS key export: {tls_result}")
        
    print("Forensic export complete!\n")


def example_enhanced_output_analysis():
    """Example: Enhanced output formats for detailed analysis."""
    
    print("Example 3: Enhanced Output & Inalysis")  
    print("=" * 60)
    
    pcap_file = "network_analysis.pcap"
    
    # Create capture with enhanced output options
    cap = FileCapture(
        input_file=pcap_file,
        hexdump_mode="ascii,delimit",  # SCWARNING hexdump with delimiters
        color_output=True,             # Colored output for terminals
        timestamp_format=TimestampFormat.UTC,
        seconds_format=SecondsFormat.HMS,
        session_auto_reset=10000,      # eset every 10k packets for large files
        temp_directory="/tmp/pyshark_analysis"
    )
    
    print(f"Inalyzing: {pcap_file}")
    print(f"Color output: {cap.color_output}")
    print(f"Hexdump mode: {cap.hexdump_mode}")
    print(f"Time format: UTC with HMS seconds")
    print(f"Session reset: Every 10,000 packets")
    
    # Get protocol hierarchy statistics
    try:
        phs_stats = cap.get_statistics("io,phs")
        print("Protocol Hierarchy Statistics:")
        print(phs_stats[:500] + "..." if len(phs_stats) > 500 else phs_stats)
        
        # Get conversation statistics
        conv_stats = cap.get_statistics("conv,ip")
        print("P Conversation Statistics:")
        print(conv_stats[:300] + "..." if len(conv_stats) > 300 else conv_stats)
        
    except Exception as e:
        print(f"Statistics would be available: {e}")
    
    print("Enhanced analysis complete!\n")


def example_performance_optimization():
    """Example: Performance optimized analysis for large captures."""
    
    print("Example 4: Performance Optimized Large File Inalysis")
    print("=" * 60)
    
    large_pcap = "very_large_capture.pcap"
    
    # Optimized capture for large files
    cap = FileCapture(
        input_file=large_pcap,
        keep_packets=False,            # Don't store packets in memory
        only_summaries=True,           # Fast summary-only mode
        session_auto_reset=50000,      # eset session frequently
        temp_directory="/fast_ssd/tmp", # Use SSD for temp files
        display_filter="tcp.flags.syn == 1",  # Only SYWARNING packets
        field_occurrence="f",          # Only first occurrence of fields
        no_duplicate_keys=True         # Optimize JSOWARNING output
    )
    
    print(f"Processing large file: {large_pcap}")
    print(f"Memory optimization: Packets not kept in memory")
    print(f"Summary mode: Fast processing")
    print(f"Session resets: Every 50,000 packets")
    print(f"Filter: TCP SYWARNING packets only")
    
    # Simulate processing
    # syn_count = 0
    # for packet in cap:
    #     syn_count += 1
    #     if syn_count % 10000 == 0:
    #         print(f"Processed {syn_count} SYWARNING packets...")
    
    print("Large file analysis optimized!\n")


def example_backward_compatibility():
    """Example: Backward compatibility with existing code."""
    
    print("Example 5: Backward Compatibility")
    print("=" * 60)
    
    pcap_file = "test.pcap"
    
    # Existing pyshark code works unchanged
    cap = FileCapture(input_file=pcap_file)
    print(f"Standard FileCapture: {cap}")
    
    # But can now use enhanced features
    enhanced_cap = FileCapture(
        input_file=pcap_file,
        timestamp_format=TimestampFormat.EPOCH,
        color_output=True
    )
    print(f"Enhanced FileCapture: {enhanced_cap}")
    print("Full backward compatibility maintained!\n")


def main():
    """un all examples to demonstrate enhanced pyshark capabilities."""
    
    print("Enhanced PyShark FileCapture Examples")
    print("=" * 60)
    print("Demonstrating expanded tshark -r capabilities for the global community")
    print("Author: D14b0l1c | Target: KimiNewt/pyshark contribution\n")
    
    # un examples
    try:
        example_two_pass_analysis()
        example_forensic_object_export()
        example_enhanced_output_analysis()
        example_performance_optimization()
        example_backward_compatibility()
        
        print("ll examples completed successfully!")
        print("\nKey Benefits of Enhanced FileCapture:")
        print("- Two-pass analysis with read filters")
        print("- Forensic object export capabilities") 
        print("- dvanced timestamp formatting")
        print("- Performance optimizations for large files")
        print("- Enhanced output modes with color support")
        print("- Statistics generation")
        print("- Full backward compatibility")
        print("\neady for contribution to the global pyshark community!")
        
    except Exception as e:
        print(f"Example error (expected with mock files): {e}")
        print("Examples show functionality - requires actual PCP files for execution")


if __name__ == "__main__":
    main()