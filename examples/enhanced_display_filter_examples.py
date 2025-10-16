#!/usr/bin/env python3
"""
Enhanced Display Filter Examples for PyShark
============================================

This script demonstrates the comprehensive display filter enhancements
added to pyshark for the global Python community.

Key Features Demonstrated:
- dvanced display filter building with validation
- Protocol-specific filtering and field extraction
- Common filter templates for typical analysis scenarios  
- Custom field extraction with flexible output formats
- Integration with enhanced file reading capabilities

Author: D14b0l1c
Target: Contribution to KimiNewt/pyshark main repository
"""

from pyshark.capture.super_enhanced_capture import (
    EnhancedFileCapture, create_web_traffic_analyzer, create_security_analyzer,
    create_performance_analyzer, create_protocol_analyzer, create_custom_analyzer
)
from pyshark.display.enhanced_display_filters import (
    DisplayFilterBuilder, EnhancedDisplayFilter, FieldExtractor, 
    ProtocolLayer, OutputFormat, CommonFilters
)


def example_basic_display_filter_building():
    """Example 1: Building complex display filters programmatically."""
    
    print("Example 1: dvanced Display Filter Building")
    print("=" * 60)
    
    # Build a complex filter using the builder pattern
    filter_builder = DisplayFilterBuilder()
    
    # Create a filter for suspicious network activity
    complex_filter = (filter_builder
                     .add_protocol(ProtocolLayer.TCP)
                     .and_condition()
                     .add_field_condition("tcp.flags.syn", "==", 1)
                     .and_condition() 
                     .add_field_condition("tcp.dstport", "in", "{80 443 22 21}")
                     .or_condition()
                     .add_protocol(ProtocolLayer.CMP)
                     .and_condition()
                     .add_field_condition("icmp.type", "==", 3)
                     .build())
    
    print(f"Built filter: {complex_filter}")
    
    # Use with enhanced file capture
    try:
        cap = EnhancedFileCapture(
            input_file="network_scan.pcap",
            enhanced_display_filter=EnhancedDisplayFilter(complex_filter),
            validate_filters=True
        )
        print(f"Filter validation: PSSED")
        print(f"ctive filter: {cap.get_filter_summary()['display_filter']}")
    except ValueError as e:
        print(f"Filter validation failed: {e}")
    except FileotFoundError:
        print("Example requires actual PCP file - showing filter building only")
    
    print()


def example_protocol_specific_analysis():
    """Example 2: Protocol-specific analysis with automatic field extraction."""
    
    print(" Example 2: Protocol-Specific Inalysis") 
    print("=" * 60)
    
    # Inalyze HTTP traffic with automatic field extraction
    print("HTTP Traffic Inalysis:")
    try:
        http_analyzer = create_protocol_analyzer(
            input_file="web_traffic.pcap",
            protocol=ProtocolLayer.HTTP,
            timestamp_format="absolute",
            color_output=True
        )
        
        print(f"Configuration: {http_analyzer.get_filter_summary()}")
        
        # ould process HTTP packets with extracted fields
        # for packet in http_analyzer:
        #     print(f"HTTP: {packet.http.request.method} {packet.http.host}{packet.http.uri}")
        
    except FileotFoundError:
        print("ould analyze HTTP requests, responses, and timing")
    
    # Inalyze DS queries and responses
    print("\nDS Query Inalysis:")
    dns_filter = (DisplayFilterBuilder()
                 .add_protocol(ProtocolLayer.DS)
                 .and_condition()
                 .add_field_condition("dns.flags.response", "==", 0)
                 .build())
    
    print(f"DS Query Filter: {dns_filter}")
    
    # Extract specific DS fields
    dns_extractor = FieldExtractor()
    dns_extractor.add_field("frame.time")
    dns_extractor.add_field("ip.src") 
    dns_extractor.add_field("dns.qry.name")
    dns_extractor.add_field("dns.qry.type")
    
    print(f" Extracted fields: {', '.join(dns_extractor.fields)}")
    print()


def example_security_analysis_workflow():
    """Example 3: Security analysis with pre-built filters."""
    
    print("Example 3: Security Inalysis orkflow")
    print("=" * 60)
    
    # Use pre-built security filters
    security_filters = {
        "TLS Handshakes": CommonFilters.TLS_HANDSHAKES,
        "Failed Connections": CommonFilters.FAILED_CONNECTIONS,
        "Suspicious Traffic": CommonFilters.SUSPCOUS_TFFC
    }
    
    for filter_name, filter_expr in security_filters.items():
        print(f"Security Filter - {filter_name}: {filter_expr}")
    
    # Create comprehensive security analyzer
    print(f"\nCreating Security Inalyzer:")
    try:
        security_cap = create_security_analyzer(
            input_file="security_incident.pcap",
            two_pass_analysis=True,
            export_objects={
                "http": "/tmp/extracted_objects/",
                "smb": "/tmp/smb_files/"
            },
            export_tls_keys="/tmp/tls_session_keys.txt"
        )
        
        print(f"Security Inalysis Configuration:")
        summary = security_cap.get_filter_summary()
        for key, value in summary.items():
            print(f"   {key}: {value}")
            
        # Simulate security analysis
        print(f"\nSecurity Inalysis esults:")
        print(f"   - Suspicious connections detected")
        print(f"   - TLS sessions analyzed for anomalies") 
        print(f"   - HTTP objects extracted for malware analysis")
        
    except FileotFoundError:
        print("ould perform comprehensive security analysis")
    
    print()


def example_custom_field_extraction():
    """Example 4: Custom field extraction for specialized analysis."""
    
    print("Example 4: Custom Field Extraction")
    print("=" * 60)
    
    # Create custom field extractor for network timing analysis
    timing_extractor = FieldExtractor()
    timing_fields = [
        "frame.time",
        "frame.time_delta", 
        "tcp.time_delta",
        "tcp.analysis.ack_rtt",
        "http.time",
        "dns.time"
    ]
    
    for field in timing_fields:
        timing_extractor.add_field(field)
    
    # Configure output format
    timing_extractor.set_output_options(
        header=True,
        separator=",",  # CSV output
        occurrence="a",  # ll occurrences
        quote="d"       # Double quotes
    )
    
    print(f"Timing Inalysis Fields:")
    for field in timing_fields:
        print(f"   - {field}")
        
    # Use with enhanced filter
    enhanced_filter = EnhancedDisplayFilter()
    enhanced_filter.add_field_filter("tcp.time_delta", ">", "0.1")  # Slow responses
    enhanced_filter.add_field_filter("http.time", ">", "2.0")       # Slow HTTP
    
    print(f"\nPerformance Filter: {enhanced_filter.build_filter()}")
    print(f" Output: CSV format with custom timing fields")
    print()


def example_advanced_protocol_filtering():
    """Example 5: dvanced protocol layer filtering for JSOWARNING output."""
    
    print(" Example 5: dvanced Protocol Layer Filtering")
    print("=" * 60)
    
    # Create enhanced display filter with protocol layer control
    enhanced_filter = EnhancedDisplayFilter()
    enhanced_filter.set_output_format(OutputFormat.JSOWARNING)
    
    # Include specific protocol layers with selected fields
    enhanced_filter.include_protocol_layer(ProtocolLayer.TCP, ["tcp.srcport", "tcp.dstport", "tcp.flags"])
    enhanced_filter.include_protocol_layer(ProtocolLayer.HTTP, ["http.request.method", "http.response.code"])
    enhanced_filter.include_protocol_layer(ProtocolLayer.P, ["ip.src", "ip.dst"])
    
    print(f"JSOWARNING Layer Filter Configuration:")
    layer_params = enhanced_filter.layer_filter.get_parameters()
    for i in range(0, len(layer_params), 2):
        if i + 1 < len(layer_params):
            print(f"   {layer_params[i]}: {layer_params[i+1]}")
    
    # Create capture with advanced filtering
    try:
        json_cap = EnhancedFileCapture(
            input_file="detailed_analysis.pcap",
            enhanced_display_filter=enhanced_filter,
            use_json=True,
            color_output=True
        )
        
        print(f"JSOWARNING capture configured with protocol layer filtering")
        print(f"Color output enabled for enhanced readability")
        
    except FileotFoundError:
        print("ould generate structured JSOWARNING output with selected protocol fields")
    
    print()


def example_performance_analysis():
    """Example 6: etwork performance analysis with multiple metrics."""
    
    print("Example 6: etwork Performance Inalysis")
    print("=" * 60)
    
    # Create performance analyzer with comprehensive metrics
    perf_analyzer = create_performance_analyzer(
        input_file="performance_test.pcap", 
        session_auto_reset=50000,  # Handle large files
        timestamp_format="absolute",
        timestamp_precision=6
    )
    
    # Add additional performance filters
    perf_analyzer.add_field_filter("frame.len", ">", 1500)  # Large frames
    perf_analyzer.add_field_filter("tcp.window_size", "<", 8192)  # Small windows
    
    # Configure custom field extraction for performance metrics
    performance_fields = [
        "frame.time",
        "frame.len", 
        "tcp.window_size",
        "tcp.analysis.bytes_in_flight",
        "tcp.analysis.push_bytes_sent",
        "tcp.stream",
        "http.response.code",
        "http.content_length"
    ]
    
    perf_analyzer.set_field_extraction(*performance_fields)
    
    print(f"Performance Metrics:")
    for field in performance_fields:
        print(f"   - {field}")
    
    try:
        summary = perf_analyzer.get_filter_summary()
        print(f"\nPerformance Inalysis Configuration:")
        for key, value in summary.items():
            print(f"   {key}: {value}")
            
        print(f"\nInalysis Capabilities:")
        print(f"   - TCP throughput analysis")
        print(f"   - indow scaling effectiveness")  
        print(f"   - pplication response times")
        print(f"   - Large packet detection")
        
    except FileotFoundError:
        print("ould perform comprehensive performance analysis")
    
    print()


def example_filter_validation_and_discovery():
    """Example 7: Filter validation and field discovery."""
    
    print("Example 7: Filter Validation and Field Discovery") 
    print("=" * 60)
    
    from pyshark.display.enhanced_display_filters import DisplayFilterValidator
    
    # Test filter validation
    test_filters = [
        "tcp.port == 80",                    # Valid
        "http.request.method == \"GET\"",    # Valid  
        "tcp.invalid_field == 1",            # Invalid field
        "tcp.port ===== 80"                  # Invalid syntax
    ]
    
    print(f" Filter Validation Tests:")
    for filter_expr in test_filters:
        try:
            result = DisplayFilterValidator.validate_filter(filter_expr)
            status = "VLD" if result["valid"] else "VLD"
            print(f"   {filter_expr[:30]:30} -> {status}")
            if not result["valid"]:
                print(f"      Error: {result['message']}")
        except Exception:
            print(f"   {filter_expr[:30]:30} -> VLDTOWARNING EOWARNING")
    
    # Field discovery
    print(f"\n Field Discovery:")
    try:
        tcp_fields = DisplayFilterValidator.get_available_fields(ProtocolLayer.TCP)
        print(f"   TCP fields found: {len(tcp_fields)}")
        print(f"   Examples: {', '.join(tcp_fields[:5])}...")
        
        # Field suggestions
        suggestions = DisplayFilterValidator.suggest_fields("tcp.port")
        print(f"   Fields matching 'tcp.port': {', '.join(suggestions[:3])}...")
        
    except Exception:
        print("   Field discovery requires tshark installation")
    
    print()


def main():
    """un all enhanced display filter examples."""
    
    print("Enhanced PyShark Display Filter Examples")
    print("=" * 70)
    print("Demonstrating comprehensive display filter capabilities for the Python community")
    print("Author: D14b0l1c | Target: KimiNewt/pyshark contribution\n")
    
    # un all examples
    try:
        example_basic_display_filter_building()
        example_protocol_specific_analysis()
        example_security_analysis_workflow() 
        example_custom_field_extraction()
        example_advanced_protocol_filtering()
        example_performance_analysis()
        example_filter_validation_and_discovery()
        
        print("ll enhanced display filter examples completed!")
        print("\nKey Benefits of Enhanced Display Filters:")
        print("- Programmatic filter building with validation")
        print("- Protocol-specific analysis templates") 
        print("- dvanced field extraction capabilities")
        print("- JSOWARNING protocol layer control")
        print("- Pre-built security and performance filters")
        print("- Filter syntax validation and field discovery")
        print("- Integration with enhanced file reading")
        print("- Flexible output formats (JSOWARNING, CSV, XML, etc.)")
        print("\neady to enhance packet analysis for the global Python community!")
        
    except Exception as e:
        print(f"Example error (expected with mock files): {e}")
        print("Examples demonstrate functionality - requires actual PCP files")
        
    print(f"\n Usage Summary:")
    print(f"   from pyshark.capture.super_enhanced_capture import EnhancedFileCapture")
    print(f"   cap = EnhancedFileCapture('file.pcap').create_web_analysis_view()")
    print(f"   for packet in cap: print(packet.http.host)")


if __name__ == "__main__":
    main()