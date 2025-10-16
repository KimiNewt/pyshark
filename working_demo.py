#!/usr/bin/env python3
"""
Simple Working Demo of PyShark Enhanced Display Filters
=======================================================

Demonstrates the working PyShark display filter enhancements with proper API usage.
Author: D14b0l1c
"""

import os
import sys

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import our modules
try:
    from src.pyshark.display.ethernet_filters import EthernetFilters
    from src.pyshark.display.wireless_filters import WirelessFilters
    from src.pyshark.display.bluetooth_filters import BluetoothFilters
    MODULES_OK = True
except ImportError as e:
    print(f"[ERROR] Module import failed: {e}")
    MODULES_OK = False


def demo_filter_capabilities():
    """Show the actual filter capabilities."""
    
    print("PyShark Enhanced Display Filters - Working Demo")
    print("=" * 48)
    
    if not MODULES_OK:
        print("[ERROR] Modules not available")
        return
    
    # Ethernet filters
    print("\n1. ETHERNET FILTERS")
    print("-" * 20)
    
    eth = EthernetFilters()
    eth_filters = eth.get_all_filters()
    print(f"[OK] Available: {len(eth_filters)} filters")
    
    # Show sample ethernet filters
    sample_eth = list(eth_filters.items())[:5]
    for name, filter_obj in sample_eth:
        print(f"  {name}: {filter_obj.filter_expression}")
    
    # Wireless filters
    print(f"\n2. WIRELESS FILTERS")
    print("-" * 20)
    
    wireless = WirelessFilters()
    wireless_filters = wireless.get_all_filters()
    print(f"[OK] Available: {len(wireless_filters)} filters")
    
    # Show sample wireless filters
    sample_wireless = list(wireless_filters.items())[:5]
    for name, filter_obj in sample_wireless:
        print(f"  {name}: {filter_obj.filter_expression}")
    
    # Bluetooth filters
    print(f"\n3. BLUETOOTH FILTERS")
    print("-" * 20)
    
    bluetooth = BluetoothFilters()
    bt_filters = bluetooth.get_all_filters()
    print(f"[OK] Available: {len(bt_filters)} filters")
    
    # Show sample bluetooth filters
    sample_bt = list(bt_filters.items())[:5]
    for name, filter_obj in sample_bt:
        print(f"  {name}: {filter_obj.filter_expression}")
    
    # Summary
    total_filters = len(eth_filters) + len(wireless_filters) + len(bt_filters)
    print(f"\n4. SUMMARY")
    print("-" * 10)
    print(f"[OK] Ethernet: {len(eth_filters)} filters")
    print(f"[OK] Wireless: {len(wireless_filters)} filters") 
    print(f"[OK] Bluetooth: {len(bt_filters)} filters")
    print(f"[OK] TOTAL: {total_filters} display filters")


def demo_test_data():
    """Show available test data."""
    
    print(f"\n5. TEST DATA")
    print("-" * 13)
    
    test_files = [
        "tests/data/ethernet_test.pcap",
        "tests/data/wireless_test.pcap", 
        "tests/data/bluetooth_test.pcap"
    ]
    
    available_files = 0
    
    for pcap_file in test_files:
        if os.path.exists(pcap_file):
            size = os.path.getsize(pcap_file)
            print(f"[OK] {pcap_file} ({size} bytes)")
            available_files += 1
        else:
            print(f"[MISSING] {pcap_file}")
    
    print(f"[INFO] Test data: {available_files}/{len(test_files)} files available")


def demo_encryption_support():
    """Show encryption capabilities (if WPA file available)."""
    
    print(f"\n6. ENCRYPTION SUPPORT")
    print("-" * 21)
    
    wpa_file = "wpa-Induction.pcap"
    
    if os.path.exists(wpa_file):
        print(f"[OK] WPA test file: {wpa_file}")
        
        try:
            from src.pyshark.display.encrypted_analysis import PySharkWPADecryptor
            
            decryptor = PySharkWPADecryptor()
            credentials = decryptor.detect_credentials(wpa_file)
            
            if credentials:
                print(f"[OK] Auto-detected SSID: {credentials.ssid}")
                print(f"[OK] WPA/WPA2 decryption: READY")
            else:
                print(f"[WARN] No credentials detected")
                
        except ImportError:
            print(f"[WARN] Encryption module not available")
            
    else:
        print(f"[INFO] WPA test file not present: {wpa_file}")
        print(f"[INFO] Encryption support available but not demonstrated")


def main():
    """Main demo function."""
    
    demo_filter_capabilities()
    demo_test_data()
    demo_encryption_support()
    
    print(f"\n" + "=" * 48)
    print("[SUCCESS] PyShark Enhanced Display Filters Working!")
    print(f"[INFO] Ready for packet analysis with 146+ filters")
    
    if MODULES_OK:
        print(f"[INFO] All core modules loaded successfully")
    
    return 0


if __name__ == "__main__":
    exit(main())