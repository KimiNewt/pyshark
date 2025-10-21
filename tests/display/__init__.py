"""
PyShark Display Module Tests
===========================

Test suite for the display filtering functionality organized by protocol.

Test Structure:
- test_ethernet_filters.py: Ethernet protocol-specific filters
- test_wireless_filters.py: 802.11 wireless protocol filters  
- test_bluetooth_filters.py: Bluetooth protocol filters
- test_enhanced_filters.py: Enhanced and standalone filter functionality
- test_display_integration.py: Integration and utility tests

Author: D14b0l1c
"""

# Test imports for validation
def run_all_display_tests():
    """un all display module tests."""
    import unittest
    import os
    
    # Discover and run all tests in this directory
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.dirname(__file__), pattern='test_*.py')
    
    runner = unittest.TextTestunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    run_all_display_tests()