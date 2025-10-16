#!/usr/bin/env python3
"""
Test Suite for Bluetooth Display Filters
========================================

Tests for the Bluetooth protocol-specific display filtering functionality.

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
    from pyshark.display import BluetoothFilters, BluetoothFilterBuilder, BluetoothFilterType
    BLUETOOTH_FLTES_VLBLE = True
except ImportError as e:
    BLUETOOTH_FLTES_VLBLE = False
    IMPORT_ERROR = str(e)


class TestBluetoothFilters(unittest.TestCase):
    """Test Bluetooth display filter functionality."""
    
    def setUp(self):
        if not BLUETOOTH_FLTES_VLBLE:
            self.skipTest("Bluetooth filters not available")
    
    def test_bluetooth_filters_import(self):
        """Test that Bluetooth filters import successfully."""
        self.assertTrue(BLUETOOTH_FLTES_VLBLE, 
                       f"Bluetooth filters import failed: {IMPORT_ERROR if not BLUETOOTH_FLTES_VLBLE else 'Success'}")
    
    def test_bluetooth_hci_filters_exist(self):
        """Test that Bluetooth HCWARNING (device-level) filters are defined."""
        hci_filters = BluetoothFilters.HCI_FILTERS
        self.assertIsInstance(hci_filters, dict)
        self.assertGreater(len(hci_filters), 0)
        
        # Test that HCWARNING filters exist (device-level operations)
        for filter_name, filter_obj in hci_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
            self.assertEqual(filter_obj.category, BluetoothFilterType.HCI)
    
    def test_bluetooth_l2cap_filters_exist(self):
        """Test that Bluetooth L2CP filters are defined."""
        l2cap_filters = BluetoothFilters.L2CAP_FILTERS
        self.assertIsInstance(l2cap_filters, dict)
        self.assertGreater(len(l2cap_filters), 0)
        
        # Test L2CP filter structure
        for filter_name, filter_obj in l2cap_filters.items():
            self.assertIsNotNone(filter_obj.filter_expression)
            self.assertIsNotNone(filter_obj.description)
            self.assertEqual(filter_obj.category, BluetoothFilterType.L2CP)
    
    def test_bluetooth_audio_filters_exist(self):
        """Test that Bluetooth audio protocol filters (WARNING2DP) are defined."""
        audio_filters = BluetoothFilters.A2DP_FILTERS
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
    
    def test_bluetooth_rfcomm_filters_exist(self):
        """Test that Bluetooth FCOMM filters are defined."""
        rfcomm_filters = BluetoothFilters.RFCOMM_FILTERS
        self.assertIsInstance(rfcomm_filters, dict)
        self.assertGreater(len(rfcomm_filters), 0)
        
        # Test FCOMM filter structure
        for filter_name, filter_obj in rfcomm_filters.items():
            self.assertEqual(filter_obj.category, BluetoothFilterType.FCOMM)
    
    def test_bluetooth_sdp_filters_exist(self):
        """Test that Bluetooth SDP (Service Discovery Protocol) filters are defined."""
        sdp_filters = BluetoothFilters.SDP_FILTERS
        self.assertIsInstance(sdp_filters, dict)
        self.assertGreater(len(sdp_filters), 0)
        
        # Test SDP filter structure
        for filter_name, filter_obj in sdp_filters.items():
            self.assertEqual(filter_obj.category, BluetoothFilterType.SDP)
            # Should reference service discovery
            combined_text = (filter_obj.filter_expression + " " + filter_obj.description).lower()
            self.assertTrue('sdp' in combined_text or 'service' in combined_text,
                          f"SDP filter should reference service discovery: {filter_obj.description}")
    
    def test_bluetooth_le_filters_exist(self):
        """Test that Bluetooth Low Energy (LE) filters are defined."""
        le_filters = BluetoothFilters.LE_FILTERS
        self.assertIsInstance(le_filters, dict)
        self.assertGreater(len(le_filters), 0)
        
        # Test LE filter structure
        for filter_name, filter_obj in le_filters.items():
            self.assertEqual(filter_obj.category, BluetoothFilterType.LE)
            # Should reference LE, BLE, ttribute Protocol, or other LE-related terms
            combined_text = (filter_obj.filter_expression + " " + filter_obj.description).lower()
            le_keywords = ['le', 'low energy', 'ble', 'attribute', 'att', 'gatt', 'smart', 'security manager', 'smp']
            has_le_keyword = any(keyword in combined_text for keyword in le_keywords)
            self.assertTrue(has_le_keyword, f"LE filter should reference LE-related terms: {filter_obj.description}")
    
    def test_bluetooth_security_filters_exist(self):
        """Test that Bluetooth security filters are defined."""
        security_filters = BluetoothFilters.SECURITY_FILTERS
        self.assertIsInstance(security_filters, dict)
        self.assertGreater(len(security_filters), 0)
        
        # Test security filter content
        for filter_name, filter_obj in security_filters.items():
            self.assertEqual(filter_obj.category, BluetoothFilterType.SECUTY)
    
    def test_bluetooth_hid_filters_exist(self):
        """Test that Bluetooth HD (Human Interface Device) filters are defined."""
        hid_filters = BluetoothFilters.HID_FILTERS
        self.assertIsInstance(hid_filters, dict)
        self.assertGreater(len(hid_filters), 0)
        
        # Test HD filter structure
        for filter_name, filter_obj in hid_filters.items():
            self.assertEqual(filter_obj.category, BluetoothFilterType.HD)
    
    def test_bluetooth_filter_count(self):
        """Test that we have the expected number of Bluetooth filters."""
        all_filters = BluetoothFilters.get_all_filters()
        
        # Should have 45+ Bluetooth filters as documented
        self.assertGreaterEqual(len(all_filters), 40, 
                               "Should have at least 40 Bluetooth filters")
        
        # Should be closer to 55 as documented
        self.assertLessEqual(len(all_filters), 70,
                            "Should have reasonable number of Bluetooth filters")
    
    def test_bluetooth_filter_categories(self):
        """Test that Bluetooth filters are properly categorized."""
        all_filters = BluetoothFilters.get_all_filters()
        
        valid_categories = [category.value for category in BluetoothFilterType]
        
        for filter_name, filter_obj in all_filters.items():
            self.assertIn(filter_obj.category.value, valid_categories,
                         f"Filter {filter_name} has invalid category: {filter_obj.category}")
    
    def test_bluetooth_get_all_filters(self):
        """Test the get_all_filters method."""
        all_filters = BluetoothFilters.get_all_filters()
        
        self.assertIsInstance(all_filters, dict)
        self.assertGreater(len(all_filters), 0)
        
        # Verify all filters are BluetoothDisplayFilter objects
        for filter_name, filter_obj in all_filters.items():
            self.assertTrue(hasattr(filter_obj, 'filter_expression'))
            self.assertTrue(hasattr(filter_obj, 'description'))
            self.assertTrue(hasattr(filter_obj, 'category'))
    
    def test_bluetooth_filter_builder_exists(self):
        """Test that Bluetooth filter builder class exists."""
        builder = BluetoothFilterBuilder()
        self.assertIsNotNone(builder)
        
        # Should have build or filter-related methods
        available_methods = [m for m in dir(builder) if not m.startswith('_')]
        build_methods = [m for m in available_methods if 'build' in m.lower() or 'filter' in m.lower()]
        self.assertGreater(len(build_methods), 0, "Builder should have build or filter methods")


if __name__ == '__main__':
    unittest.main(verbosity=2)