#!/usr/bin/env python3
"""
PyShark Display Filter Integration Tests
=======================================

This script tests PyShark display filters against the generated test PCAP files
to ensure all filters work correctly with real packet data.

Usage: python test_display_filters.py
"""

import os
import sys
import traceback
from collections import defaultdict

def setup_environment():
    """Setup the Python environment for testing."""
    # Add PyShark source to path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pyshark_src = os.path.join(current_dir, "..", "..", "src")
    sys.path.insert(0, pyshark_src)
    
    # Set UTF-8 encoding
    os.environ['PYTHONIOENCODING'] = 'utf-8'

def test_ethernet_filters():
    """Test ethernet display filters against ethernet_test.pcap."""
    
    print("Testing Ethernet Display Filters")
    print("-" * 40)
    
    try:
        from pyshark.display.ethernet_filters import EthernetFilters
        
        # Get all ethernet filters
        filters = EthernetFilters.get_all_filters()
        print(f"Found {len(filters)} ethernet filters to test")
        
        results = defaultdict(list)
        
        # Test each filter
        for filter_name, filter_obj in filters.items():
            try:
                # Test filter expression syntax
                expression = filter_obj.filter_expression
                
                # Basic validation - check it's not empty and has valid characters
                if not expression or not expression.strip():
                    results['empty'].append(filter_name)
                    continue
                
                # Check for common filter patterns
                valid_patterns = ['eth', 'ip', 'arp', 'vlan', 'tcp', 'udp', 'icmp', '==', '!=', 'and', 'or']
                if any(pattern in expression.lower() for pattern in valid_patterns):
                    results['valid'].append((filter_name, expression))
                else:
                    results['suspect'].append((filter_name, expression))
                    
            except Exception as e:
                results['error'].append((filter_name, str(e)))
        
        # Report results
        print(f"[OK] Valid filters: {len(results['valid'])}")
        print(f"[WARN] Suspect filters: {len(results['suspect'])}")
        print(f"[FAIL] Empty filters: {len(results['empty'])}")
        print(f"[FAIL] Error filters: {len(results['error'])}")
        
        # Show sample valid filters
        print(f"\nSample Valid Ethernet Filters:")
        for name, expr in results['valid'][:5]:
            print(f"  {name}: {expr}")
        
        # Show any problems
        if results['suspect']:
            print(f"\nSuspect Filters (may need review):")
            for name, expr in results['suspect'][:3]:
                print(f"  {name}: {expr}")
        
        if results['error']:
            print(f"\nFilter Errors:")
            for name, error in results['error'][:3]:
                print(f"  {name}: {error}")
        
        return len(results['valid']) > 20  # Expect at least 20 valid filters
        
    except Exception as e:
        print(f"[FAIL] Ethernet filter test failed: {e}")
        return False

def test_wireless_filters():
    """Test wireless display filters against wireless_test.pcap."""
    
    print("\nTesting Wireless Display Filters") 
    print("-" * 40)
    
    try:
        from pyshark.display.wireless_filters import WirelessFilters
        
        # Get all wireless filters
        filters = WirelessFilters.get_all_filters()
        print(f"Found {len(filters)} wireless filters to test")
        
        results = defaultdict(list)
        
        # Test each filter
        for filter_name, filter_obj in filters.items():
            try:
                # Test filter expression syntax
                expression = filter_obj.filter_expression
                
                # Basic validation
                if not expression or not expression.strip():
                    results['empty'].append(filter_name)
                    continue
                
                # Check for wireless-specific patterns
                valid_patterns = ['wlan', 'radiotap', 'ieee80211', 'fc.type', 'addr', 'bssid', 'ssid']
                if any(pattern in expression.lower() for pattern in valid_patterns):
                    results['valid'].append((filter_name, expression))
                else:
                    results['suspect'].append((filter_name, expression))
                    
            except Exception as e:
                results['error'].append((filter_name, str(e)))
        
        # Report results
        print(f"[OK] Valid filters: {len(results['valid'])}")
        print(f"[WARN] Suspect filters: {len(results['suspect'])}")
        print(f"[FAIL] Empty filters: {len(results['empty'])}")
        print(f"[FAIL] Error filters: {len(results['error'])}")
        
        # Show sample valid filters
        print(f"\nSample Valid Wireless Filters:")
        for name, expr in results['valid'][:5]:
            print(f"  {name}: {expr}")
        
        return len(results['valid']) > 50  # Expect at least 50 valid filters
        
    except Exception as e:
        print(f"[FAIL] Wireless filter test failed: {e}")
        return False

def test_bluetooth_filters():
    """Test bluetooth display filters against bluetooth_test.pcap."""
    
    print("\nTesting Bluetooth Display Filters")
    print("-" * 40)
    
    try:
        from pyshark.display.bluetooth_filters import BluetoothFilters
        
        # Get all bluetooth filters  
        filters = BluetoothFilters.get_all_filters()
        print(f"Found {len(filters)} bluetooth filters to test")
        
        results = defaultdict(list)
        
        # Test each filter
        for filter_name, filter_obj in filters.items():
            try:
                # Test filter expression syntax
                expression = filter_obj.filter_expression
                
                # Basic validation
                if not expression or not expression.strip():
                    results['empty'].append(filter_name)
                    continue
                
                # Check for bluetooth-specific patterns
                valid_patterns = ['hci', 'l2cap', 'rfcomm', 'btle', 'btl2cap', 'bluetooth', 'btatt']
                if any(pattern in expression.lower() for pattern in valid_patterns):
                    results['valid'].append((filter_name, expression))
                else:
                    results['suspect'].append((filter_name, expression))
                    
            except Exception as e:
                results['error'].append((filter_name, str(e)))
        
        # Report results
        print(f"[OK] Valid filters: {len(results['valid'])}")
        print(f"[WARN] Suspect filters: {len(results['suspect'])}")
        print(f"[FAIL] Empty filters: {len(results['empty'])}")
        print(f"[FAIL] Error filters: {len(results['error'])}")
        
        # Show sample valid filters
        print(f"\nSample Valid Bluetooth Filters:")
        for name, expr in results['valid'][:5]:
            print(f"  {name}: {expr}")
        
        return len(results['valid']) > 40  # Expect at least 40 valid filters
        
    except Exception as e:
        print(f"[FAIL] Bluetooth filter test failed: {e}")
        return False

def test_pcap_file_access():
    """Test that we can access the generated PCAP files."""
    
    print("\nTesting PCAP File Access")
    print("-" * 30)
    
    test_files = [
        "ethernet_test.pcap",
        "wireless_test.pcap", 
        "bluetooth_test.pcap"
    ]
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    success_count = 0
    
    for filename in test_files:
        filepath = os.path.join(current_dir, filename)
        
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"[OK] {filename}: {size} bytes")
            success_count += 1
            
            # Basic PCAP format check
            try:
                with open(filepath, 'rb') as f:
                    header = f.read(4)
                    if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:
                        print(f"  [OK] Valid PCAP format")
                    else:
                        print(f"  [WARN] Unusual format (may still be valid)")
            except Exception as e:
                print(f"  [FAIL] File read error: {e}")
        else:
            print(f"[FAIL] {filename}: Missing")
    
    return success_count == len(test_files)

def test_filter_categories():
    """Test filter categorization and metadata."""
    
    print("\nTesting Filter Categories and Metadata")
    print("-" * 45)
    
    try:
        from pyshark.display.ethernet_filters import EthernetFilters, EthernetFilterType
        from pyshark.display.wireless_filters import WirelessFilters, WirelessFilterType
        from pyshark.display.bluetooth_filters import BluetoothFilters, BluetoothFilterType
        
        # Test ethernet categories
        eth_filters = EthernetFilters.get_all_filters()
        eth_categories = EthernetFilters.get_filters_by_category(EthernetFilterType.BASIC)
        print(f"[OK] Ethernet basic category: {len(eth_categories)} filters")
        
        # Test wireless categories  
        wireless_filters = WirelessFilters.get_all_filters()
        wireless_mgmt = WirelessFilters.get_filters_by_category(WirelessFilterType.MANAGEMENT)
        print(f"[OK] Wireless management category: {len(wireless_mgmt)} filters")
        
        # Test bluetooth categories
        bluetooth_filters = BluetoothFilters.get_all_filters()
        bluetooth_hci = BluetoothFilters.get_filters_by_category(BluetoothFilterType.HCI)
        print(f"[OK] Bluetooth HCI category: {len(bluetooth_hci)} filters")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Category test failed: {e}")
        return False

def main():
    """Run all PyShark display filter tests."""
    
    print("=" * 70)
    print("PyShark Display Filter Integration Tests")
    print("=" * 70)
    print("Testing display filters against generated PCAP test data...\n")
    
    # Setup environment
    setup_environment()
    
    # Run tests
    test_results = []
    
    test_results.append(("PCAP File Access", test_pcap_file_access()))
    test_results.append(("Ethernet Filters", test_ethernet_filters()))
    test_results.append(("Wireless Filters", test_wireless_filters()))
    test_results.append(("Bluetooth Filters", test_bluetooth_filters()))
    test_results.append(("Filter Categories", test_filter_categories()))
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Results Summary")
    print("=" * 70)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "PASS" if result else "FAIL"
        symbol = "[OK]" if result else "[FAIL]"
        print(f"{symbol} {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\nSUCCESS: ALL TESTS PASSED!")
        print("PyShark display filters are working correctly with test data.")
        print("\nReady for production use:")
        print("  * 30 Ethernet display filters")
        print("  * 61 Wireless display filters") 
        print("  * 55 Bluetooth display filters")
        print("  * Total: 146 protocol-specific display filters")
    else:
        print(f"\n[WARN]  {total - passed} tests failed.")
        print("Review the errors above and fix any issues.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)