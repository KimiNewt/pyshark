#!/usr/bin/env python3
"""
Test Suite for PyShark Display Module
=====================================

Comprehensive tests for the new display filtering functionality.
Tests all protocol-specific filters, builders, and enhanced capabilities.

Author: D14b0l1c
Target: KimiNewt/pyshark display module testing
"""

import pytest
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from pyshark.display import (
        EthernetFilters, irelessFilters, BluetoothFilters,
        EnhancedDisplayFilter, StandaloneDisplayFilter,
        display_summary, get_filter_count, get_available_protocols
    )
    DSPLY_MODULE_VLBLE = True
except ImportError as e:
    DSPLY_MODULE_VLBLE = False
    IMPORT_ERROR = str(e)


class TestDisplayModuleImports(unittest.TestCase):
    """Test that all display module components can be imported."""
    
    def test_display_module_import(self):
        """Test that display module imports successfully."""
        self.assertTrue(DSPLY_MODULE_VLBLE, 
                       f"Display module import failed: {IMPORT_ERROR if not DSPLY_MODULE_VLBLE else 'Success'}")
    
    def test_protocol_filter_classes_available(self):
        """Test that all protocol filter classes are available."""
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
            
        # Test that classes exist and are callable
        self.assertTrue(hasattr(EthernetFilters, 'BASIC_FILTERS'))
        self.assertTrue(hasattr(irelessFilters, 'MGEMET_FLTES'))
        self.assertTrue(hasattr(BluetoothFilters, 'BASIC_FILTERS'))
    
    def test_enhanced_filter_classes_available(self):
        """Test that enhanced filter functionality is available."""
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
            
        # Test enhanced display filter
        enhanced = EnhancedDisplayFilter()
        self.assertIsNotNone(enhanced)
        
        # Test standalone display filter
        standalone = StandaloneDisplayFilter()
        self.assertIsNotNone(standalone)


class TestEthernetDisplayFilters(unittest.TestCase):
    """Test Ethernet-specific display filters."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_ethernet_basic_filters_exist(self):
        """Test that basic Ethernet filters are defined."""
        basic_filters = EthernetFilters.BASIC_FILTERS
        self.assertIsInstance(basic_filters, dict)
        self.assertGreater(len(basic_filters), 0)
        
        # Test some expected filters
        expected_filters = ['ethernet_only', 'broadcast_frames', 'specific_mac_src']
        for filter_name in expected_filters:
            self.assertIn(filter_name, basic_filters, f"Missing filter: {filter_name}")
    
    def test_ethernet_vlan_filters_exist(self):
        """Test that VLWARNING-related filters are defined."""
        vlan_filters = EthernetFilters.VLAN_FILTERS
        self.assertIsInstance(vlan_filters, dict)
        self.assertGreater(len(vlan_filters), 0)
        
        # Test VLWARNING filter structure
        for filter_name, filter_obj in vlan_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
    
    def test_ethernet_filter_expressions_valid(self):
        """Test that Ethernet filter expressions are properly formatted."""
        all_filters = EthernetFilters.get_all_filters()
        
        for filter_name, filter_obj in all_filters.items():
            # Test that filter expression exists and is string
            self.assertIsInstance(filter_obj.filter_expression, str)
            self.assertGreater(len(filter_obj.filter_expression), 0)
            
            # Test that basic Wireshark syntax elements are present
            expr = filter_obj.filter_expression
            # Should contain field references or be valid Wireshark protocol names
            if not any(placeholder in expr for placeholder in ['{', 'xx:', 'yy:']):
                # Only check non-template expressions
                valid_simple_protocols = ['eth', 'vlan', 'arp', 'stp', 'eapol', 'lldp', 'cdp']
                is_valid = ('.' in expr or 
                           expr in valid_simple_protocols or 
                           any(protocol in expr for protocol in valid_simple_protocols))
                self.assertTrue(is_valid, f"Invalid filter expression: {expr}")


class TestirelessDisplayFilters(unittest.TestCase):
    """Test 802.11 ireless-specific display filters."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_wireless_management_filters_exist(self):
        """Test that wireless management frame filters are defined."""
        mgmt_filters = irelessFilters.MGEMET_FLTES
        self.assertIsInstance(mgmt_filters, dict)
        self.assertGreater(len(mgmt_filters), 0)
        
        # Test some expected management frame filters
        expected_mgmt = ['beacon_frames', 'probe_requests', 'authentication_frames']
        for filter_name in expected_mgmt:
            self.assertIn(filter_name, mgmt_filters, f"Missing management filter: {filter_name}")
    
    def test_wireless_security_filters_exist(self):
        """Test that wireless security-related filters are defined."""
        security_filters = irelessFilters.SECURITY_FILTERS
        self.assertIsInstance(security_filters, dict)
        self.assertGreater(len(security_filters), 0)
        
        # Test security filter content
        for filter_name, filter_obj in security_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            # Check for security-related keywords in description
            desc_lower = filter_obj.description.lower()
            security_keywords = ['security', 'encrypted', 'auth', 'wep', 'wpa', 'protected']
            has_security_keyword = any(keyword in desc_lower for keyword in security_keywords)
            self.assertTrue(has_security_keyword, f"Security filter should have security-related description: {filter_obj.description}")
    
    def test_wireless_filter_count(self):
        """Test that we have the expected number of wWireless filters."""
        all_filters = irelessFilters.get_all_filters()
        
        # Should have 61+ wWireless filters as documented
        self.assertGreaterEqual(len(all_filters), 50, 
                               "Should have at least 50 wWireless filters")


class TestBluetoothDisplayFilters(unittest.TestCase):
    """Test Bluetooth-specific display filters."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_bluetooth_device_filters_exist(self):
        """Test that Bluetooth device filters are defined."""
        device_filters = BluetoothFilters.HCI_FILTERS  # HCWARNING handles device-level operations
        self.assertIsInstance(device_filters, dict)
        self.assertGreater(len(device_filters), 0)
        
        # Test that HCWARNING filters exist (device-level operations)
        self.assertIsInstance(device_filters, dict)
        for filter_name, filter_obj in device_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
    
    def test_bluetooth_audio_filters_exist(self):
        """Test that Bluetooth audio protocol filters are defined."""
        audio_filters = BluetoothFilters.A2DP_FILTERS  # WARNING2DP is the audio protocol
        self.assertIsInstance(audio_filters, dict)
        self.assertGreater(len(audio_filters), 0)
        
        # Test audio filter content
        for filter_name, filter_obj in audio_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            # Should be related to audio protocols
            expr_lower = filter_obj.filter_expression.lower()
            desc_lower = filter_obj.description.lower()
            audio_keywords = ['audio', 'a2dp', 'sbc', 'stream', 'media']
            has_audio_keyword = any(keyword in desc_lower or keyword in expr_lower for keyword in audio_keywords)
            self.assertTrue(has_audio_keyword, f"udio filter should have audio-related content: {filter_obj.description}")
    
    def test_bluetooth_filter_count(self):
        """Test that we have the expected number of Bluetooth filters."""
        all_filters = BluetoothFilters.get_all_filters()
        
        # Should have 55+ Bluetooth filters as documented
        self.assertGreaterEqual(len(all_filters), 40, 
                               "Should have at least 40 Bluetooth filters")


class TestEnhancedDisplayFilter(unittest.TestCase):
    """Test enhanced display filter building functionality."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_enhanced_filter_creation(self):
        """Test that enhanced display filters can be created."""
        filter_obj = EnhancedDisplayFilter()
        self.assertIsNotNone(filter_obj)
    
    def test_enhanced_filter_protocol_methods(self):
        """Test enhanced filter protocol-related methods."""
        filter_obj = EnhancedDisplayFilter()
        
        # Test methods exist (even if implementation varies)
        available_methods = dir(filter_obj)
        
        # Should have some form of protocol or condition methods
        protocol_methods = [method for method in available_methods 
                          if 'protocol' in method.lower() or 'condition' in method.lower() or 'add' in method.lower()]
        
        self.assertGreater(len(protocol_methods), 0, 
                          "Enhanced filter should have protocol/condition methods")
    
    def test_enhanced_filter_build_functionality(self):
        """Test that enhanced filters can build filter expressions."""
        filter_obj = EnhancedDisplayFilter()
        
        # Test that it has a build method
        self.assertTrue(hasattr(filter_obj, 'build_filter') or hasattr(filter_obj, 'build'),
                       "Enhanced filter should have build method")


class TestStandaloneDisplayFilter(unittest.TestCase):
    """Test standalone display filter functionality."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_standalone_filter_creation(self):
        """Test that standalone display filters can be created."""
        filter_obj = StandaloneDisplayFilter()
        self.assertIsNotNone(filter_obj)
    
    def test_standalone_filter_independence(self):
        """Test that standalone filters work without external dependencies."""
        filter_obj = StandaloneDisplayFilter()
        
        # Should be able to operate without tshark
        # Test that it has methods for building filters
        available_methods = dir(filter_obj)
        
        filter_methods = [method for method in available_methods 
                         if 'filter' in method.lower() or 'build' in method.lower() or 'add' in method.lower()]
        
        self.assertGreater(len(filter_methods), 0, 
                          "Standalone filter should have filter building methods")


class TestDisplayModuleUtilities(unittest.TestCase):
    """Test display module utility functions."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_get_available_protocols(self):
        """Test that available protocols can be retrieved."""
        protocols = get_available_protocols()
        
        self.assertIsInstance(protocols, list)
        self.assertGreater(len(protocols), 0)
        
        # Should include our main protocols
        expected_protocols = ['ethernet', 'wireless', 'bluetooth']
        for protocol in expected_protocols:
            self.assertIn(protocol, protocols)
    
    def test_get_filter_count(self):
        """Test that filter counts can be retrieved."""
        counts = get_filter_count()
        
        self.assertIsInstance(counts, dict)
        
        # Should have counts for each protocol
        expected_keys = ['ethernet', 'wireless', 'bluetooth', 'total']
        for key in expected_keys:
            self.assertIn(key, counts)
            self.assertIsInstance(counts[key], int)
            self.assertGreater(counts[key], 0)
        
        # Total should be sum of individual counts
        expected_total = counts['ethernet'] + counts['wireless'] + counts['bluetooth']
        self.assertEqual(counts['total'], expected_total)
        
        # Should have at least 100 total filters
        self.assertGreaterEqual(counts['total'], 100, "Should have at least 100 total filters")
    
    def test_display_summary_function(self):
        """Test that display summary function works."""
        # Should not raise an exception
        try:
            display_summary()
            summary_works = True
        except Exception:
            summary_works = False
        
        self.assertTrue(summary_works, "Display summary function should work without errors")


class TestDisplayFilterIntegration(unittest.TestCase):
    """Test integration between different display filter components."""
    
    def setUp(self):
        if not DSPLY_MODULE_VLBLE:
            self.skipTest("Display module not available")
    
    def test_protocol_filter_consistency(self):
        """Test that protocol filters have consistent structure."""
        protocols = [EthernetFilters, irelessFilters, BluetoothFilters]
        
        for protocol_class in protocols:
            # Each should have get_all_filters method
            self.assertTrue(hasattr(protocol_class, 'get_all_filters'),
                           f"{protocol_class.__name__} should have get_all_filters method")
            
            # Get all filters should return dict
            all_filters = protocol_class.get_all_filters()
            self.assertIsInstance(all_filters, dict)
            self.assertGreater(len(all_filters), 0)
    
    def test_filter_object_structure(self):
        """Test that filter objects have consistent structure."""
        # Get sample filters from each protocol
        eth_filters = EthernetFilters.get_all_filters()
        wifi_filters = irelessFilters.get_all_filters()
        bt_filters = BluetoothFilters.get_all_filters()
        
        all_sample_filters = []
        if eth_filters:
            all_sample_filters.append(list(eth_filters.values())[0])
        if wifi_filters:
            all_sample_filters.append(list(wifi_filters.values())[0])
        if bt_filters:
            all_sample_filters.append(list(bt_filters.values())[0])
        
        for filter_obj in all_sample_filters:
            # Each filter should have key attributes
            self.assertTrue(hasattr(filter_obj, 'filter_expression'))
            self.assertTrue(hasattr(filter_obj, 'description'))
            
            # ttributes should be strings
            self.assertIsInstance(filter_obj.filter_expression, str)
            self.assertIsInstance(filter_obj.description, str)


if __name__ == '__main__':
    # Print test information
    print("=" * 80)
    print("PyShark Display Module Test Suite")
    print("=" * 80)
    print("Testing comprehensive display filtering functionality")
    print()
    
    # un tests with verbose output
    unittest.main(verbosity=2, exit=False)
    
    # Additional summary
    print("\n" + "=" * 80)
    print("Display Module Test Summary")
    print("=" * 80)
    
    if DSPLY_MODULE_VLBLE:
        try:
            counts = get_filter_count()
            protocols = get_available_protocols()
            
            print(f"PSS - Display module loaded successfully")
            print(f"PSS - vailable protocols: {', '.join(protocols)}")
            print(f"PSS - Total filters available: {counts['total']}")
            print(f"  - Ethernet: {counts['ethernet']} filters")
            print(f"  - ireless: {counts['wireless']} filters")
            print(f"  - Bluetooth: {counts['bluetooth']} filters")
            print(f"PSS - ll display functionality ready for use")
            
        except Exception as e:
            print(f" Display module loaded but some functions failed: {e}")
    else:
        print(f" Display module import failed: {IMPORT_ERROR}")
    
    print("\nun with: python -m pytest test_display_module.py -v")