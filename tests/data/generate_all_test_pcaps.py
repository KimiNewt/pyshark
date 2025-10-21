#!/usr/bin/env python3
"""
Generate All Test PCAP Files for PyShark Display Filter Testing
==============================================================

This script runs all three pcap generators to create test data for
ethernet, wireless, and bluetooth display filter validation.

Dependencies: scapy
Usage: python generate_all_test_pcaps.py
Output: ethernet_test.pcap, wireless_test.pcap, bluetooth_test.pcap
"""

import os
import sys
import subprocess

def main():
    """Generate all test pcap files."""
    
    print("=" * 70)
    print("PyShark Display Filter Test Data Generator")
    print("=" * 70)
    print("Generating test PCAP files for all protocol types...")
    print()
    
    scripts = [
        ("generate_ethernet_test.py", "Ethernet"),
        ("generate_wireless_test.py", "802.11 Wireless"), 
        ("generate_bluetooth_test.py", "Bluetooth")
    ]
    
    success_count = 0
    
    for script, protocol in scripts:
        print(f"Running {protocol} test generator...")
        print("-" * 40)
        
        try:
            # Run the script
            result = subprocess.run([sys.executable, script], 
                                  capture_output=True, text=True, cwd=os.path.dirname(__file__))
            
            if result.returncode == 0:
                print(result.stdout)
                success_count += 1
                print(f"[OK] {protocol} test data generated successfully\n")
            else:
                print(f"[FAIL] {protocol} generator failed:")
                print(result.stderr)
                print()
                
        except Exception as e:
            print(f"[FAIL] Error running {script}: {e}\n")
    
    # Summary
    print("=" * 70)
    print(f"Test Data Generation Summary: {success_count}/{len(scripts)} successful")
    print("=" * 70)
    
    if success_count == len(scripts):
        print("SUCCESS: All test PCAP files generated successfully!")
        print("\nGenerated files:")
        
        test_files = ["ethernet_test.pcap", "wireless_test.pcap", "bluetooth_test.pcap"]
        for test_file in test_files:
            file_path = os.path.join(os.path.dirname(__file__), test_file)
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                print(f"  [OK] {test_file} ({size} bytes)")
            else:
                print(f"  [MISSING] {test_file}")
        
        print(f"\nUsage in PyShark tests:")
        print(f"  import pyshark")
        print(f"  cap = pyshark.FileCapture('tests/data/ethernet_test.pcap')")
        print(f"  # Apply your display filters and validate results")
        
        return 0
    else:
        print(f"WARNING: {len(scripts) - success_count} generators failed.")
        print("Check the error messages above and ensure Scapy is installed:")
        print("  pip install scapy")
        return 1

if __name__ == "__main__":
    exit(main())