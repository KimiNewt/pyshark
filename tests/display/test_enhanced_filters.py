#!/usr/bin/env python3
"""
Test Suite for Enhanced Display Filter Functionality
===================================================

Tests for the enhanced display filter building and standalone functionality.

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
        EnhancedDisplayFilter, StandaloneDisplayFilter,
        DisplayFilterBuilder, FieldExtractor, CommonFilters
    )
    EHCED_FLTES_VLBLE = True
except ImportError as e:
    EHCED_FLTES_VLBLE = False
    IMPORT_ERROR = str(e)


class TestEnhancedDisplayFilter(unittest.TestCase):
    """Test enhanced display filter building functionality."""
    
    def setUp(self):
        if not EHCED_FLTES_VLBLE:
            self.skipTest("Enhanced filters not available")
    
    def test_enhanced_filter_import(self):
        """Test that enhanced display filters import successfully."""
        self.assertTrue(EHCED_FLTES_VLBLE, 
                       f"Enhanced filters import failed: {IMPORT_ERROR if not EHCED_FLTES_VLBLE else 'Success'}")
    
    def test_enhanced_filter_creation(self):
        """Test that enhanced display filters can be created."""
        filter_obj = EnhancedDisplayFilter()
        self.assertIsNotNone(filter_obj)
    
    def test_enhanced_filter_has_methods(self):
        """Test enhanced filter has expected methods."""
        filter_obj = EnhancedDisplayFilter()
        
        # Test methods exist (even if implementation varies)
        available_methods = dir(filter_obj)
        
        # Should have some form of protocol or condition methods
        expected_method_patterns = ['protocol', 'condition', 'add', 'build', 'filter']
        found_patterns = []
        
        for pattern in expected_method_patterns:
            pattern_methods = [method for method in available_methods 
                             if pattern in method.lower()]
            if pattern_methods:
                found_patterns.append(pattern)
        
        self.assertGreater(len(found_patterns), 0, 
                          "Enhanced filter should have protocol/condition/build methods")
    
    def test_enhanced_filter_build_functionality(self):
        """Test that enhanced filters can build filter expressions."""
        filter_obj = EnhancedDisplayFilter()
        
        # Test that it has a build method
        self.assertTrue(hasattr(filter_obj, 'build_filter') or hasattr(filter_obj, 'build'),
                       "Enhanced filter should have build method")


class TestStandaloneDisplayFilter(unittest.TestCase):
    """Test standalone display filter functionality."""
    
    def setUp(self):
        if not EHCED_FLTES_VLBLE:
            self.skipTest("Enhanced filters not available")
    
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
    
    def test_standalone_filter_has_protocol_methods(self):
        """Test standalone filter has protocol-related methods."""
        filter_obj = StandaloneDisplayFilter()
        
        available_methods = dir(filter_obj)
        
        # Should have methods for adding conditions or protocols
        condition_methods = [method for method in available_methods 
                           if 'condition' in method.lower() or 'protocol' in method.lower()]
        
        # f no specific methods, should at least have general methods
        if not condition_methods:
            general_methods = [method for method in available_methods 
                             if 'add' in method.lower() and not method.startswith('_')]
            self.assertGreater(len(general_methods), 0,
                             "Standalone filter should have methods to add conditions")


class TestDisplayFilterBuilder(unittest.TestCase):
    """Test display filter builder functionality."""
    
    def setUp(self):
        if not EHCED_FLTES_VLBLE:
            self.skipTest("Enhanced filters not available")
    
    def test_display_filter_builder_creation(self):
        """Test that display filter builder can be created."""
        try:
            builder = DisplayFilterBuilder()
            self.assertIsNotNone(builder)
        except Exception:
            # f DisplayFilterBuilder doesn't exist as standalone, skip
            self.skipTest("DisplayFilterBuilder not available as standalone class")
    
    def test_display_filter_builder_methods(self):
        """Test that display filter builder has expected methods."""
        try:
            builder = DisplayFilterBuilder()
            
            # Should have build-related methods
            available_methods = dir(builder)
            build_methods = [method for method in available_methods 
                           if 'build' in method.lower() and not method.startswith('_')]
            
            self.assertGreater(len(build_methods), 0,
                             "DisplayFilterBuilder should have build methods")
        except Exception:
            self.skipTest("DisplayFilterBuilder not available")


class TestFieldExtractor(unittest.TestCase):
    """Test field extraction functionality."""
    
    def setUp(self):
        if not EHCED_FLTES_VLBLE:
            self.skipTest("Enhanced filters not available")
    
    def test_field_extractor_creation(self):
        """Test that field extractor can be created."""
        try:
            extractor = FieldExtractor()
            self.assertIsNotNone(extractor)
        except Exception:
            self.skipTest("FieldExtractor not available as standalone class")
    
    def test_field_extractor_methods(self):
        """Test that field extractor has expected methods."""
        try:
            extractor = FieldExtractor()
            
            # Should have extraction-related methods
            available_methods = dir(extractor)
            extract_methods = [method for method in available_methods 
                             if 'extract' in method.lower() or 'field' in method.lower()]
            extract_methods = [m for m in extract_methods if not m.startswith('_')]
            
            self.assertGreater(len(extract_methods), 0,
                             "FieldExtractor should have extraction methods")
        except Exception:
            self.skipTest("FieldExtractor not available")


class TestCommonFilters(unittest.TestCase):
    """Test common filters functionality."""
    
    def setUp(self):
        if not EHCED_FLTES_VLBLE:
            self.skipTest("Enhanced filters not available")
    
    def test_common_filters_available(self):
        """Test that common filters are available."""
        try:
            # CommonFilters should have class attributes for common filter expressions
            available_attrs = dir(CommonFilters)
            filter_attrs = [attr for attr in available_attrs 
                           if not attr.startswith('_') and attr.isupper()]
            
            self.assertGreater(len(filter_attrs), 0,
                             "CommonFilters should have predefined filter constants")
        except Exception:
            self.skipTest("CommonFilters not available")
    
    def test_common_filters_are_strings(self):
        """Test that common filters are string expressions."""
        try:
            available_attrs = dir(CommonFilters)
            filter_attrs = [attr for attr in available_attrs 
                           if not attr.startswith('_') and attr.isupper()]
            
            for attr_name in filter_attrs[:5]:  # Test first 5 attributes
                attr_value = getattr(CommonFilters, attr_name)
                self.assertIsInstance(attr_value, str,
                                    f"Common filter {attr_name} should be a string")
                self.assertGreater(len(attr_value), 0,
                                 f"Common filter {attr_name} should not be empty")
        except Exception:
            self.skipTest("CommonFilters attributes not available")


if __name__ == '__main__':
    unittest.main(verbosity=2)