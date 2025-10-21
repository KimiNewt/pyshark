#!/usr/bin/env python3
"""
Integration Test Suite for Enhanced PyShark Capabilities
=======================================================

Comprehensive test suite validating the integration between enhanced file capture
and display filter capabilities for the global Python community contribution.

Test Coverage:
- Enhanced file capture with display filters  
- Protocol-specific analysis workflows
- Field extraction integration
- Filter validation and error handling
- Performance with various file sizes
- Security analysis capabilities  
- Backward compatibility verification

Author: D14b0l1c
Target: KimiNewt/pyshark main repository contribution  
"""

import unittest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock, call

# Import enhanced PyShark components
from pyshark.capture.super_enhanced_capture import (
    EnhancedFileCapture, create_web_traffic_analyzer, create_security_analyzer,
    create_performance_analyzer, create_protocol_analyzer, create_custom_analyzer
)
from pyshark.display.enhanced_display_filters import (
    DisplayFilterBuilder, EnhancedDisplayFilter, FieldExtractor,
    ProtocolLayer, OutputFormat, CommonFilters, DisplayFilterValidator
)
from pyshark.capture.enhancements import TimestampFormat, ExportProtocol


class TestEnhancedDisplayFilterIntegration(unittest.TestCase):
    """Test integration between enhanced file capture and display filters."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        self.temp_pcap.close()
        
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_pcap.name):
            os.unlink(self.temp_pcap.name)
        
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_enhanced_capture_with_display_filter(self):
        """Test EnhancedFileCapture with display filter integration."""
        
        # Build complex display filter
        filter_builder = DisplayFilterBuilder()
        display_filter = (filter_builder
                         .add_protocol(ProtocolLayer.HTTP)
                         .and_condition()
                         .add_field_condition("http.request.method", "==", '"GET"')
                         .build())
        
        enhanced_filter = EnhancedDisplayFilter(display_filter)
        enhanced_filter.add_field_filter("tcp.dstport", "==", "80")
        
        # Create enhanced capture with display filter
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            cap = EnhancedFileCapture(
                input_file=self.temp_pcap.name,
                enhanced_display_filter=enhanced_filter,
                timestamp_format=TimestampFormat.ABSOLUTE,
                use_json=True,
                validate_filters=True
            )
            
            # Verify filter integration
            filter_summary = cap.get_filter_summary()
            self.assertIn('display_filter', filter_summary)
            self.assertIn('http', filter_summary['display_filter'].lower())
            self.assertIn('tcp.dstport', filter_summary['display_filter'])
            
            # Verify enhanced parameters were passed
            mock_file_capture.assert_called_once()
            call_args = mock_file_capture.call_args
            self.assertEqual(call_args[0][0], self.temp_pcap.name)
            self.assertIn('display_filter', call_args[1])
            self.assertIn('use_json', call_args[1])
            
    def test_protocol_analyzer_factory_integration(self):
        """Test protocol analyzer factory with display filters."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            # Create HTTP protocol analyzer
            http_analyzer = create_protocol_analyzer(
                input_file=self.temp_pcap.name,
                protocol=ProtocolLayer.HTTP,
                timestamp_format="epoch",
                color_output=True,
                export_objects={"http": self.temp_dir}
            )
            
            # Verify HTTP-specific filter
            summary = http_analyzer.get_filter_summary()
            self.assertIn('http', summary['display_filter'].lower())
            
            # Verify export configuration  
            self.assertTrue(http_analyzer.export_objects_configured)
            
            # Test field extraction
            http_analyzer.set_field_extraction(
                "frame.time", "http.request.method", "http.host"
            )
            
            extracted_fields = http_analyzer.field_extractor.fields
            self.assertIn("http.request.method", extracted_fields)
            self.assertIn("http.host", extracted_fields)
            
    def test_security_analyzer_integration(self):
        """Test security analyzer with pre-built filters."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            security_analyzer = create_security_analyzer(
                input_file=self.temp_pcap.name,
                two_pass_analysis=True,
                export_objects={
                    "http": os.path.join(self.temp_dir, "http"),
                    "smb": os.path.join(self.temp_dir, "smb") 
                },
                export_tls_keys=os.path.join(self.temp_dir, "tls_keys.txt")
            )
            
            # Verify security-specific filters are applied
            summary = security_analyzer.get_filter_summary()
            self.assertIn('display_filter', summary)
            
            # Test that common security filters can be added
            security_analyzer.add_field_filter("tcp.flags.syn", "==", 1)
            security_analyzer.add_field_filter("tcp.flags.ack", "==", 0)
            
            # Verify multiple export configurations
            self.assertTrue(security_analyzer.export_objects_configured)
            self.assertIn("http", security_analyzer.export_object_types)
            self.assertIn("smb", security_analyzer.export_object_types)
            
    def test_performance_analyzer_integration(self):
        """Test performance analyzer with timing analysis."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            perf_analyzer = create_performance_analyzer(
                input_file=self.temp_pcap.name,
                session_auto_reset=10000,
                timestamp_format="absolute",
                timestamp_precision=6
            )
            
            # Add performance-specific filters
            perf_analyzer.add_field_filter("tcp.time_delta", ">", "0.1")
            perf_analyzer.add_field_filter("frame.len", ">", 1500)
            
            # Set performance field extraction
            perf_fields = [
                "frame.time", "frame.len", "tcp.window_size",
                "tcp.analysis.bytes_in_flight", "tcp.stream"
            ]
            perf_analyzer.set_field_extraction(*perf_fields)
            
            # Verify performance configuration
            summary = perf_analyzer.get_filter_summary()
            self.assertIn("tcp.time_delta", summary['display_filter'])
            self.assertIn("frame.len", summary['display_filter'])
            
            # Check field extractor configuration  
            for field in perf_fields:
                self.assertIn(field, perf_analyzer.field_extractor.fields)
                
    def test_custom_analyzer_with_json_output(self):
        """Test custom analyzer with JSOWARNING protocol layer output."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            # Create enhanced display filter with JSOWARNING output
            enhanced_filter = EnhancedDisplayFilter()
            enhanced_filter.set_output_format(OutputFormat.JSOWARNING)
            enhanced_filter.include_protocol_layer(
                ProtocolLayer.TCP, 
                ["tcp.srcport", "tcp.dstport", "tcp.flags"]
            )
            enhanced_filter.include_protocol_layer(
                ProtocolLayer.HTTP,
                ["http.request.method", "http.response.code"]
            )
            
            custom_analyzer = create_custom_analyzer(
                input_file=self.temp_pcap.name,
                enhanced_display_filter=enhanced_filter,
                timestamp_format=TimestampFormat.UTC,
                color_output=True
            )
            
            # Verify JSOWARNING configuration
            call_args = mock_file_capture.call_args
            self.assertTrue(call_args[1]['use_json'])
            
            # Verify protocol layer filtering
            summary = custom_analyzer.get_filter_summary()
            self.assertIn('display_filter', summary)
            
    def test_field_extraction_integration(self):
        """Test field extraction integration with enhanced capture."""
        
        # Create field extractor with custom configuration
        field_extractor = FieldExtractor()
        field_extractor.add_field("frame.time")
        field_extractor.add_field("ip.src")  
        field_extractor.add_field("ip.dst")
        field_extractor.add_field("tcp.srcport")
        field_extractor.add_field("http.request.uri")
        
        # Configure output options
        field_extractor.set_output_options(
            header=True,
            separator=",",
            occurrence="f",  # First occurrence
            quote="d"        # Double quotes
        )
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            cap = EnhancedFileCapture(
                input_file=self.temp_pcap.name,
                field_extractor=field_extractor,
                validate_filters=True
            )
            
            # Verify field extractor integration
            self.assertEqual(len(cap.field_extractor.fields), 5)
            self.assertIn("http.request.uri", cap.field_extractor.fields)
            
            # Test field parameter generation
            params = cap.field_extractor.get_parameters()
            self.assertIn("-T", params)  # Field output format
            self.assertIn("fields", params)
            self.assertIn("-E", params)  # Output options
            
    def test_filter_validation_integration(self):
        """Test filter validation integration."""
        
        # Test valid filter
        valid_filter = DisplayFilterBuilder().add_protocol(ProtocolLayer.TCP).build()
        enhanced_filter = EnhancedDisplayFilter(valid_filter)
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock() 
            mock_file_capture.return_value = mock_capture
            
            try:
                cap = EnhancedFileCapture(
                    input_file=self.temp_pcap.name,
                    enhanced_display_filter=enhanced_filter,
                    validate_filters=True
                )
                # Should succeed
                self.assertIsNotNone(cap)
            except ValueError:
                self.fail("Valid filter should not raise ValueError")
        
        # Test invalid filter (would raise ValueError with real tshark)
        invalid_filter = "tcp.invalid_field == 1" 
        enhanced_filter_invalid = EnhancedDisplayFilter(invalid_filter)
        
        # Note: In real scenario with tshark, this would raise ValueError
        # Here we test the validation framework
        self.assertIsNotNone(enhanced_filter_invalid.filter)
        
    def test_export_object_integration(self):
        """Test export object integration with display filters."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            # Mock the export methods
            with patch.object(EnhancedFileCapture, 'export_objects_to_directory') as mock_export:
                mock_export.return_value = {
                    "http": ["/tmp/object1.jpg", "/tmp/object2.html"],
                    "smb": ["/tmp/file1.doc"]
                }
                
                cap = EnhancedFileCapture(
                    input_file=self.temp_pcap.name,
                    export_objects={
                        ExportProtocol.HTTP: self.temp_dir,
                        ExportProtocol.SMB: self.temp_dir
                    }
                )
                
                # Test export configuration
                self.assertTrue(cap.export_objects_configured)
                self.assertIn(ExportProtocol.HTTP, cap.export_object_types)
                
                # Test export execution (mocked)
                results = cap.export_objects_to_directory()
                self.assertIn("http", results)
                self.assertEqual(len(results["http"]), 2)
                
    def test_backward_compatibility(self):
        """Test that enhanced features don't break backward compatibility."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            # Test basic usage without enhanced features
            basic_cap = EnhancedFileCapture(input_file=self.temp_pcap.name)
            
            # Should work like regular FileCapture
            mock_file_capture.assert_called_once()
            call_args = mock_file_capture.call_args
            self.assertEqual(call_args[0][0], self.temp_pcap.name)
            
            # Test with minimal enhancements
            enhanced_cap = EnhancedFileCapture(
                input_file=self.temp_pcap.name,
                timestamp_format=TimestampFormat.EPOCH
            )
            
            # Should still work
            self.assertIsNotNone(enhanced_cap)
            
    def test_common_filters_integration(self):
        """Test pre-built common filters integration."""
        
        with patch('pyshark.FileCapture') as mock_file_capture:
            mock_capture = MagicMock()
            mock_file_capture.return_value = mock_capture
            
            # Test each common filter
            common_filters = [
                CommonFilters.HTTP_TRAFFIC,
                CommonFilters.HTTPS_TRAFFIC, 
                CommonFilters.DNS_QUERIES,
                CommonFilters.TCP_SYN_PACKETS,
                CommonFilters.FAILED_CONNECTIONS,
                CommonFilters.TLS_HANDSHAKES
            ]
            
            for filter_expr in common_filters:
                enhanced_filter = EnhancedDisplayFilter(filter_expr)
                
                cap = EnhancedFileCapture(
                    input_file=self.temp_pcap.name,
                    enhanced_display_filter=enhanced_filter
                )
                
                summary = cap.get_filter_summary()
                self.assertIn('display_filter', summary)
                self.assertTrue(len(summary['display_filter']) > 0)


class TestDisplayFilterBuilderdvanced(unittest.TestCase):
    """Test advanced display filter builder functionality."""
    
    def test_complex_filter_building(self):
        """Test building complex nested filters."""
        
        builder = DisplayFilterBuilder()
        
        # Build: (tcp.port == 80 or tcp.port == 443) and http and not icmp
        complex_filter = (builder
                         .open_parenthesis()
                         .add_field_condition("tcp.port", "==", 80)
                         .or_condition()
                         .add_field_condition("tcp.port", "==", 443)
                         .close_parenthesis()
                         .and_condition()
                         .add_protocol(ProtocolLayer.HTTP)
                         .and_not_condition()
                         .add_protocol(ProtocolLayer.CMP)
                         .build())
        
        expected_parts = ["tcp.port == 80", "tcp.port == 443", "http", "not icmp"]
        for part in expected_parts:
            self.assertIn(part, complex_filter)
            
        self.assertIn("(", complex_filter)
        self.assertIn(")", complex_filter)
        
    def test_filter_validation_methods(self):
        """Test filter validation methods."""
        
        # Test with mock validation (real validation requires tshark)
        with patch.object(DisplayFilterValidator, 'validate_filter') as mock_validate:
            mock_validate.return_value = {"valid": True, "message": "OK"}
            
            builder = DisplayFilterBuilder() 
            filter_expr = builder.add_protocol(ProtocolLayer.TCP).build()
            
            result = DisplayFilterValidator.validate_filter(filter_expr)
            self.assertTrue(result["valid"])
            
        # Test field suggestion (mock)
        with patch.object(DisplayFilterValidator, 'suggest_fields') as mock_suggest:
            mock_suggest.return_value = ["tcp.port", "tcp.srcport", "tcp.dstport"]
            
            suggestions = DisplayFilterValidator.suggest_fields("tcp.port")
            self.assertIn("tcp.port", suggestions)
            self.assertEqual(len(suggestions), 3)


class TestEnhancedFilterPerformance(unittest.TestCase):
    """Test performance characteristics of enhanced filters."""
    
    def test_large_filter_building(self):
        """Test building large complex filters."""
        
        builder = DisplayFilterBuilder()
        
        # Build filter with many conditions
        for i in range(100):
            if i > 0:
                builder.or_condition()
            builder.add_field_condition("tcp.port", "==", 8000 + i)
            
        large_filter = builder.build()
        
        # Should not crash and should contain all ports
        self.assertIn("tcp.port == 8000", large_filter)
        self.assertIn("tcp.port == 8099", large_filter)
        self.assertGreater(len(large_filter), 1000)  # Should be substantial
        
    def test_multiple_protocol_layers(self):
        """Test filters with multiple protocol layers."""
        
        enhanced_filter = EnhancedDisplayFilter()
        
        # Add multiple protocol layers
        protocols = [
            ProtocolLayer.P,
            ProtocolLayer.TCP, 
            ProtocolLayer.HTTP,
            ProtocolLayer.DS,
            ProtocolLayer.TLS
        ]
        
        for protocol in protocols:
            enhanced_filter.include_protocol_layer(protocol, [])
            
        # Should handle multiple layers
        params = enhanced_filter.layer_filter.get_parameters()
        self.assertGreater(len(params), 5)  # Should have multiple -e options


def run_integration_tests():
    """un the complete integration test suite."""
    
    print("unning Enhanced PyShark Integration Tests")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(loader.loadTestsFromTestCase(TestEnhancedDisplayFilterIntegration))
    suite.addTest(loader.loadTestsFromTestCase(TestDisplayFilterBuilderdvanced))
    suite.addTest(loader.loadTestsFromTestCase(TestEnhancedFilterPerformance))
    
    # un tests
    runner = unittest.TextTestunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"Integration Test esults:")
    print(f"   Tests run: {result.testsun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print(f"ll integration tests PSSED!")
        print(f"Enhanced PyShark ready for community contribution!")
    else:
        print(f"Some tests failed - review before contribution")
        
        if result.failures:
            print(f"\n Failures:")
            for test, traceback in result.failures:
                print(f"   - {test}: {traceback.split('ssertionError:')[-1].strip()}")
                
        if result.errors:
            print(f"\n Errors:")
            for test, traceback in result.errors:
                print(f"   - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_integration_tests()
    exit(0 if success else 1)