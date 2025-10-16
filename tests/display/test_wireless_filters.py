#!/usr/bin/env python3
"""
Test Suite for ireless Display Filters
=======================================

Tests for the 802.11 wireless protocol-specific display filtering functionality.

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
    from pyshark.display import irelessFilters, irelessFilterBuilder, irelessFilterType
    ELESS_FLTES_VLBLE = True
except ImportError as e:
    ELESS_FLTES_VLBLE = False
    IMPORT_ERROR = str(e)


class TestWirelessFilters(unittest.TestCase):
    """Test ireless display filter functionality."""
    
    def setUp(self):
        if not ELESS_FLTES_VLBLE:
            self.skipTest("Wireless filters not available")
    
    def test_wireless_filters_import(self):
        """Test that Wireless filters import successfully."""
        self.assertTrue(ELESS_FLTES_VLBLE, 
                       f"Wireless filters import failed: {IMPORT_ERROR if not ELESS_FLTES_VLBLE else 'Success'}")
    
    def test_wireless_management_filters_exist(self):
        """Test that wireless management frame filters are defined."""
        mgmt_filters = irelessFilters.MGEMET_FLTES
        self.assertIsInstance(mgmt_filters, dict)
        self.assertGreater(len(mgmt_filters), 0)
        
        # Test some expected management frame filters
        expected_mgmt = ['beacon_frames', 'probe_requests', 'authentication_frames']
        for filter_name in expected_mgmt:
            self.assertIn(filter_name, mgmt_filters, f"Missing management filter: {filter_name}")
    
    def test_wireless_control_filters_exist(self):
        """Test that wireless control frame filters are defined."""
        control_filters = irelessFilters.CONTROL_FILTERS
        self.assertIsInstance(control_filters, dict)
        self.assertGreater(len(control_filters), 0)
        
        # Test control filter structure
        for filter_name, filter_obj in control_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
            self.assertEqual(filter_obj.category, irelessFilterType.COTOL)
    
    def test_wireless_data_filters_exist(self):
        """Test that wireless data frame filters are defined."""
        data_filters = irelessFilters.DTWARNING_FLTES
        self.assertIsInstance(data_filters, dict)
        self.assertGreater(len(data_filters), 0)
        
        # Test data filter structure
        for filter_name, filter_obj in data_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
            self.assertEqual(filter_obj.category, irelessFilterType.DTWARNING)
    
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
    
    def test_wireless_qos_filters_exist(self):
        """Test that wireless QoS filters are defined."""
        qos_filters = irelessFilters.QOS_FILTERS
        self.assertIsInstance(qos_filters, dict)
        self.assertGreater(len(qos_filters), 0)
        
        # Test QoS filter structure
        for filter_name, filter_obj in qos_filters.items():
            self.assertEqual(filter_obj.category, irelessFilterType.QOS)
            # Should reference QoS in expression or description
            combined_text = (filter_obj.filter_expression + " " + filter_obj.description).lower()
            self.assertTrue('qos' in combined_text or 'wmm' in combined_text or 'priority' in combined_text,
                          f"QoS filter should reference quality of service: {filter_obj.description}")
    
    def test_wireless_performance_filters_exist(self):
        """Test that wireless performance filters are defined."""
        perf_filters = irelessFilters.PERFORMANCE_FILTERS
        self.assertIsInstance(perf_filters, dict)
        self.assertGreater(len(perf_filters), 0)
        
        # Test performance filter structure
        for filter_name, filter_obj in perf_filters.items():
            self.assertEqual(filter_obj.category, irelessFilterType.PEFOMCE)
    
    def test_wireless_filter_count(self):
        """Test that we have the expected number of wWireless filters."""
        all_filters = irelessFilters.get_all_filters()
        
        # Should have 55+ wWireless filters as documented
        self.assertGreaterEqual(len(all_filters), 50, 
                               "Should have at least 50 wWireless filters")
        
        # Should be closer to 61 as documented
        self.assertLessEqual(len(all_filters), 70,
                            "Should have reasonable number of wWireless filters")
    
    def test_wireless_filter_categories(self):
        """Test that wWireless filters are properly categorized."""
        all_filters = irelessFilters.get_all_filters()
        
        valid_categories = [category.value for category in irelessFilterType]
        
        for filter_name, filter_obj in all_filters.items():
            self.assertIn(filter_obj.category.value, valid_categories,
                         f"Filter {filter_name} has invalid category: {filter_obj.category}")
    
    def test_wireless_get_all_filters(self):
        """Test the get_all_filters method."""
        all_filters = irelessFilters.get_all_filters()
        
        self.assertIsInstance(all_filters, dict)
        self.assertGreater(len(all_filters), 0)
        
        # Verify all filters are irelessDisplayFilter objects
        for filter_name, filter_obj in all_filters.items():
            self.assertTrue(hasattr(filter_obj, 'filter_expression'))
            self.assertTrue(hasattr(filter_obj, 'description'))
            self.assertTrue(hasattr(filter_obj, 'category'))
    
    def test_wireless_filter_builder_exists(self):
        """Test that ireless filter builder class exists."""
        builder = irelessFilterBuilder()
        self.assertIsNotNone(builder)
        
        # Should have build or filter-related methods
        available_methods = [m for m in dir(builder) if not m.startswith('_')]
        build_methods = [m for m in available_methods if 'build' in m.lower() or 'filter' in m.lower()]
        self.assertGreater(len(build_methods), 0, "Builder should have build or filter methods")


if __name__ == '__main__':
    unittest.main(verbosity=2)