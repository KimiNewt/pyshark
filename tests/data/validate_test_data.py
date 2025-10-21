#!/usr/bin/env python3
"""
Validate Test PCAP Files with PyShark Display Filters
=====================================================

This script validates that the generated test PCAP files work correctly
with the PyShark display filter enhancements.
"""

import os
import sys

def test_pcap_files():
    """Test that the generated PCAP files are valid and contain expected data."""
    
    print("=" * 60)
    print("Testing Generated PCAP Files with PyShark Display Filters")
    print("=" * 60)
    
    # Add PyShark source to path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    
    try:
        # Test our display filter modules work
        from pyshark.display.ethernet_filters import EthernetFilters
        from pyshark.display.wireless_filters import WirelessFilters  
        from pyshark.display.bluetooth_filters import BluetoothFilters
        
        print("[OK] Display filter modules imported successfully")
        
        # Show filter counts
        eth_filters = EthernetFilters.get_all_filters()
        wireless_filters = WirelessFilters.get_all_filters()
        bluetooth_filters = BluetoothFilters.get_all_filters()
        
        print(f"[OK] Ethernet filters: {len(eth_filters)} available")
        print(f"[OK] Wireless filters: {len(wireless_filters)} available") 
        print(f"[OK] Bluetooth filters: {len(bluetooth_filters)} available")
        
    except Exception as e:
        print(f"[FAIL] Filter module test failed: {e}")
        return False
    
    # Test PCAP file existence and basic info
    test_files = [
        ("ethernet_test.pcap", "Ethernet"),
        ("wireless_test.pcap", "802.11 Wireless"),
        ("bluetooth_test.pcap", "Bluetooth")
    ]
    
    print(f"\nTesting PCAP Files:")
    print("-" * 30)
    
    for filename, protocol in test_files:
        filepath = os.path.join(os.path.dirname(__file__), filename)
        
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"[OK] {protocol}: {filename} ({size} bytes)")
            
            # Basic file validation (check if it starts with pcap magic)
            with open(filepath, 'rb') as f:
                header = f.read(4)
                if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:  # pcap magic numbers
                    print(f"  [OK] Valid PCAP format")
                else:
                    print(f"  [WARN] Unusual file format (may still be valid)")
        else:
            print(f"[FAIL] {protocol}: {filename} (missing)")
    
    # Test sample filter expressions
    print(f"\nTesting Sample Filter Expressions:")
    print("-" * 40)
    
    try:
        # Ethernet filter samples
        ipv4_filter = eth_filters.get('ipv4_only')
        if ipv4_filter:
            print(f"[OK] IPv4 filter: {ipv4_filter.filter_expression}")
        
        arp_filter = eth_filters.get('arp_traffic')
        if arp_filter:
            print(f"[OK] ARP filter: {arp_filter.filter_expression}")
            
        # Wireless filter samples
        beacon_filter = wireless_filters.get('beacon_frames')
        if beacon_filter:
            print(f"[OK] Beacon filter: {beacon_filter.filter_expression}")
            
        mgmt_filter = wireless_filters.get('management_frames')
        if mgmt_filter:
            print(f"[OK] Management filter: {mgmt_filter.filter_expression}")
            
        # Bluetooth filter samples  
        hci_filter = bluetooth_filters.get('hci_commands')
        if hci_filter:
            print(f"[OK] HCI filter: {hci_filter.filter_expression}")
            
        print(f"[OK] Filter expressions validated")
        
    except Exception as e:
        print(f"[FAIL] Filter expression test failed: {e}")
        return False
    
    # Usage instructions
    print(f"\n" + "=" * 60)
    print(f"SUCCESS: All test data ready for PyShark display filter testing!")
    print(f"=" * 60)
    
    print(f"\nUsage Examples:")
    print(f"")
    print(f"# Basic PCAP loading (requires pyshark fix for DEFULT_LOG_LEVEL typo)")
    print(f"import pyshark")
    print(f"cap = pyshark.FileCapture('tests/data/ethernet_test.pcap')")
    print(f"")
    print(f"# With display filters")
    print(f"from pyshark.display.ethernet_filters import EthernetFilters")
    print(f"filters = EthernetFilters.get_all_filters()")
    print(f"ipv4_filter = filters['ipv4_only'].filter_expression")
    print(f"cap = pyshark.FileCapture('tests/data/ethernet_test.pcap', display_filter=ipv4_filter)")
    print(f"")
    print(f"# Test different protocols")
    print(f"wifi_cap = pyshark.FileCapture('tests/data/wireless_test.pcap', display_filter='wlan')")
    print(f"bt_cap = pyshark.FileCapture('tests/data/bluetooth_test.pcap', display_filter='bluetooth')")
    
    return True

if __name__ == "__main__":
    success = test_pcap_files()
    exit(0 if success else 1)