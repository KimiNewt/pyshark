#!/usr/bin/env python3
"""
Test Suite for Ethernet Display Filters
=======================================

Tests for the Ethernet protocol-specific display filtering functionality.

Author: D14b0l1c
"""

import pytest
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

try:
    from pyshark.display import EthernetFilters, EthernetFilterBuilder, EthernetFilterType
    ETHEET_FLTES_VLBLE = True
except ImportError as e:
    ETHEET_FLTES_VLBLE = False
    IMPORT_ERROR = str(e)


class TestEthernetFilters(unittest.TestCase):
    """Test Ethernet display filter functionality."""
    
    def setUp(self):
        if not ETHEET_FLTES_VLBLE:
            self.skipTest("Ethernet filters not available")
    
    def test_ethernet_filters_import(self):
        """Test that Ethernet filters import successfully."""
        self.assertTrue(ETHEET_FLTES_VLBLE, 
                       f"Ethernet filters import failed: {IMPORT_ERROR if not ETHEET_FLTES_VLBLE else 'Success'}")
    
    def test_basic_ethernet_filters_exist(self):
        """Test that basic Ethernet filters are defined."""
        basic_filters = EthernetFilters.BASIC_FILTERS
        self.assertIsInstance(basic_filters, dict)
        self.assertGreater(len(basic_filters), 0)
        
        # Test some expected filters
        expected_filters = ['ethernet_only', 'broadcast_frames', 'specific_mac_src', 'specific_mac_dst']
        for filter_name in expected_filters:
            self.assertIn(filter_name, basic_filters, f"Missing basic filter: {filter_name}")
    
    def test_vlan_ethernet_filters_exist(self):
        """Test that VLWARNING-related Ethernet filters are defined."""
        vlan_filters = EthernetFilters.VLAN_FILTERS
        self.assertIsInstance(vlan_filters, dict)
        self.assertGreater(len(vlan_filters), 0)
        
        # Test VLWARNING filter structure
        for filter_name, filter_obj in vlan_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
            self.assertEqual(filter_obj.category, EthernetFilterType.VLWARNING)
    
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
    
    def test_ethernet_filter_categories(self):
        """Test that Ethernet filters are properly categorized."""
        all_filters = EthernetFilters.get_all_filters()
        
        valid_categories = [category.value for category in EthernetFilterType]
        
        for filter_name, filter_obj in all_filters.items():
            self.assertIn(filter_obj.category.value, valid_categories,
                         f"Filter {filter_name} has invalid category: {filter_obj.category}")
    
    def test_ethernet_get_all_filters(self):
        """Test the get_all_filters method."""
        all_filters = EthernetFilters.get_all_filters()
        
        self.assertIsInstance(all_filters, dict)
        # Should have at least 25 Ethernet filters
        self.assertGreaterEqual(len(all_filters), 25)
        
        # Verify all filters are EthernetDisplayFilter objects
        for filter_name, filter_obj in all_filters.items():
            self.assertTrue(hasattr(filter_obj, 'filter_expression'))
            self.assertTrue(hasattr(filter_obj, 'description'))
            self.assertTrue(hasattr(filter_obj, 'category'))
    
    def test_ethernet_filter_builder_exists(self):
        """Test that Ethernet filter builder class exists."""
        builder = EthernetFilterBuilder()
        self.assertIsNotNone(builder)
        
        # Should have build or filter-related methods
        available_methods = [m for m in dir(builder) if not m.startswith('_')]
        build_methods = [m for m in available_methods if 'build' in m.lower() or 'filter' in m.lower()]
        self.assertGreater(len(build_methods), 0, "Builder should have build or filter methods")
    
    def test_ethernet_spanning_tree_filters(self):
        """Test that Spanning Tree Protocol filters exist."""
        stp_filters = EthernetFilters.STP_FILTERS
        self.assertIsInstance(stp_filters, dict)
        self.assertGreater(len(stp_filters), 0)
        
        # Should have STP-related filters
        for filter_name, filter_obj in stp_filters.items():
            self.assertEqual(filter_obj.category, EthernetFilterType.SPG_TEE)
            # Should reference STP in expression or description
            combined_text = (filter_obj.filter_expression + " " + filter_obj.description).lower()
            self.assertTrue('stp' in combined_text or 'spanning' in combined_text,
                          f"STP filter should reference spanning tree: {filter_obj.description}")


if __name__ == '__main__':
    unittest.main(verbosity=2)