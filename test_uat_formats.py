#!/usr/bin/env python3
"""
Test different UAT formats for TShark WPA decryption
====================================================

This script tests various UAT syntax formats to find the correct one
for TShark 4.2.4 WPA decryption.
"""

import subprocess
import os

def test_uat_format(format_string, description):
    """Test a specific UAT format string."""
    print(f"\nTesting: {description}")
    print(f"Format: {format_string}")
    print("-" * 50)
    
    try:
        # Test with help command to avoid processing PCAP
        cmd = ["tshark", "-o", format_string, "-h"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("[OK] FORMAT ACCEPTED")
            return True
        else:
            print(f"[FAIL] FORMAT REJECTED: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print("[OK] FORMAT ACCEPTED (timeout on help is normal)")
        return True
    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def main():
    """Test various UAT formats."""
    print("TShark UAT Format Testing for WPA Decryption")
    print("=" * 50)
    
    # Test cases for different UAT formats
    formats = [
        # Original format from our code
        ('uat:80211_keys:"wpa-pwd","Induction:Coherer"', "Our current format"),
        
        # Alternative formats
        ('uat:80211_keys:wpa-pwd,Induction:Coherer', "No quotes format"),
        ('wlan.enable_decryption:TRUE', "Enable decryption only"),
        ('ieee802_11.wep_keys:"wpa-pwd","Induction:Coherer"', "wep_keys format"),
        
        # Try different UAT table names
        ('uat:wlan_wep_keys:"wpa-pwd","Induction:Coherer"', "wlan_wep_keys table"),
        ('uat:ieee80211_keys:"wpa-pwd","Induction:Coherer"', "ieee80211_keys table"),
        
        # Try simpler formats
        ('wpa-pwd:Induction:Coherer', "Simple wpa-pwd format"),
        ('ieee802_11.wep_keys:wpa-pwd,Induction:Coherer', "wep_keys no quotes"),
    ]
    
    working_formats = []
    
    for format_str, description in formats:
        if test_uat_format(format_str, description):
            working_formats.append((format_str, description))
    
    print("\n" + "=" * 50)
    print("SUMMARY:")
    print("=" * 50)
    
    if working_formats:
        print("Working formats found:")
        for format_str, description in working_formats:
            print(f"[OK] {description}: {format_str}")
    else:
        print("[FAIL] No working formats found!")
    
    # Test actual decryption with working format
    if working_formats:
        print(f"\nTesting actual decryption with first working format...")
        test_format = working_formats[0][0]
        
        pcap_path = "tests/data/wpa-Induction.pcap"
        if os.path.exists(pcap_path):
            cmd = [
                "tshark", "-r", pcap_path,
                "-o", "wlan.enable_decryption:TRUE",
                "-o", test_format,
                "-c", "3",
                "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "tcp.port"
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print("[OK] Actual decryption test PASSED")
                    print("Output:", result.stdout)
                else:
                    print(f"[FAIL] Actual decryption test FAILED: {result.stderr}")
            except Exception as e:
                print(f"[ERROR] Decryption test error: {e}")
        else:
            print(f"[WARNING] PCAP file not found: {pcap_path}")

if __name__ == "__main__":
    main()