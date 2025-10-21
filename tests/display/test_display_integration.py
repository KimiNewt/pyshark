#!/usr/bin/env python3
"""
Test Suite for Display Module Integration
========================================

Tests for overall display module integration and utility functions.

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
    from pyshark.display import (
        display_summary, get_filter_count, get_available_protocols,
        EthernetFilters, irelessFilters, BluetoothFilters
    )
    DSPLY_TEGTOWARNING_VLBLE = True
except ImportError as e:
    DSPLY_TEGTOWARNING_VLBLE = False
    IMPORT_ERROR = str(e)


class TestDisplayModuleUtilities(unittest.TestCase):
    """Test display module utility functions."""
    
    def setUp(self):
        if not DSPLY_TEGTOWARNING_VLBLE:
            self.skipTest("Display module not available")
    
    def test_display_module_import(self):
        """Test that display module utilities import successfully."""
        self.assertTrue(DSPLY_TEGTOWARNING_VLBLE, 
                       f"Display module import failed: {IMPORT_ERROR if not DSPLY_TEGTOWARNING_VLBLE else 'Success'}")
    
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
    
    def test_filter_count_matches_actual_filters(self):
        """Test that reported filter counts match actual available filters."""
        counts = get_filter_count()
        
        # Get actual filter counts
        eth_actual = len(EthernetFilters.get_all_filters())
        wifi_actual = len(irelessFilters.get_all_filters())
        bt_actual = len(BluetoothFilters.get_all_filters())
        
        # eported counts should match actual counts
        self.assertEqual(counts['ethernet'], eth_actual,
                        f"eported Ethernet count ({counts['ethernet']}) doesn't match actual ({eth_actual})")
        self.assertEqual(counts['wireless'], wifi_actual,
                        f"eported ireless count ({counts['wireless']}) doesn't match actual ({wifi_actual})")
        self.assertEqual(counts['bluetooth'], bt_actual,
                        f"eported Bluetooth count ({counts['bluetooth']}) doesn't match actual ({bt_actual})")


class TestDisplayFilterIntegration(unittest.TestCase):
    """Test integration between different display filter components."""
    
    def setUp(self):
        if not DSPLY_TEGTOWARNING_VLBLE:
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
            self.assertTrue(hasattr(filter_obj, 'category'))
            
            # ttributes should be of correct types
            self.assertIsInstance(filter_obj.filter_expression, str)
            self.assertIsInstance(filter_obj.description, str)
            
            # Should not be empty
            self.assertGreater(len(filter_obj.filter_expression), 0)
            self.assertGreater(len(filter_obj.description), 0)
    
    def test_all_protocols_have_basic_filters(self):
        """Test that all protocols have basic filter categories."""
        protocols = [EthernetFilters, irelessFilters, BluetoothFilters]
        
        for protocol_class in protocols:
            # Each should have BASIC_FILTERS
            self.assertTrue(hasattr(protocol_class, 'BASIC_FILTERS'),
                           f"{protocol_class.__name__} should have BASIC_FILTERS")
            
            basic_filters = getattr(protocol_class, 'BASIC_FILTERS')
            self.assertIsInstance(basic_filters, dict)
            self.assertGreater(len(basic_filters), 0)
    
    def test_filter_expressions_are_valid_format(self):
        """Test that filter expressions follow valid Wireshark format."""
        protocols = [EthernetFilters, irelessFilters, BluetoothFilters]
        
        for protocol_class in protocols:
            all_filters = protocol_class.get_all_filters()
            
            for filter_name, filter_obj in all_filters.items():
                expr = filter_obj.filter_expression
                
                # Should not contain obviously invalid characters
                invalid_chars = ['\n', '\r', '\t']
                for char in invalid_chars:
                    self.assertotIn(char, expr, 
                                   f"Filter {filter_name} contains invalid character: {repr(char)}")
                
                # Should not be just whitespace
                self.assertTrue(expr.strip(), f"Filter {filter_name} is empty or whitespace")


if __name__ == '__main__':
    unittest.main(verbosity=2)