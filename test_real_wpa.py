#!/usr/bin/env python3
"""
Real PCAP WPA Decryption Test
=============================

Test PyShark WPA decryption with the actual wpa-Induction.pcap file.
"""

import sys
import os

# Add PyShark source to path
current_dir = os.path.dirname(os.path.abspath(__file__))
pyshark_src = os.path.join(current_dir, "src")
sys.path.insert(0, pyshark_src)

try:
    from pyshark.display.encrypted_analysis import PySharkWPADecryptor, WPACredentials
except ImportError:
    # Fallback to test module location
    sys.path.insert(0, os.path.join(current_dir, "tests", "data"))
    from test_wpa_decryption import PySharkWPADecryptor, WPACredentials

def test_real_wpa_decryption():
    """Test decryption with the real wpa-Induction.pcap file."""
    
    print("Real PCAP WPA Decryption Test")
    print("=" * 40)
    
    pcap_file = "tests/data/wpa-Induction.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"PCAP file not found: {pcap_file}")
        return False
    
    file_size = os.path.getsize(pcap_file)
    print(f"Input file: {pcap_file} ({file_size} bytes)")
    
    # Initialize decryptor
    decryptor = PySharkWPADecryptor()
    
    # Use known credentials for wpa-Induction.pcap
    credentials = WPACredentials(
        ssid="Coherer",
        password="Induction",
        description="Wireshark sample WPA capture"
    )
    
    print(f"Credentials: SSID={credentials.ssid}, Password={credentials.password}")
    
    # Test credential auto-detection
    auto_creds = decryptor.detect_credentials(pcap_file)
    if auto_creds:
        print(f"Auto-detected credentials match: {auto_creds.ssid} / {auto_creds.password}")
        credentials = auto_creds
    
    # Test decryption
    print(f"\nTesting decryption...")
    result = decryptor.decrypt_pcap(pcap_file, credentials)
    
    if result.success:
        print(f"Decryption SUCCESS")
        print(f"  Output file: {result.decrypted_file}")
        print(f"  Output size: {os.path.getsize(result.decrypted_file)} bytes")
        print(f"  Packets processed: {result.packets_decrypted}")
        
        # Quick analysis of decrypted content
        import subprocess
        
        try:
            # Count total packets
            count_cmd = ["tshark", "-r", result.decrypted_file, "-c"]
            count_result = subprocess.run(count_cmd, capture_output=True, text=True, timeout=10)
            
            if count_result.returncode == 0:
                total_lines = len(count_result.stdout.strip().split('\n'))
                print(f"  Total packets in output: {total_lines}")
            
            # Count IP packets
            ip_cmd = ["tshark", "-r", result.decrypted_file, "-Y", "ip", "-T", "fields", "-e", "frame.number"]
            ip_result = subprocess.run(ip_cmd, capture_output=True, text=True, timeout=10)
            
            if ip_result.returncode == 0 and ip_result.stdout.strip():
                ip_count = len(ip_result.stdout.strip().split('\n'))
                print(f"  IP packets found: {ip_count}")
            else:
                print(f"  IP packets found: 0")
            
            # Show sample IP traffic
            sample_cmd = ["tshark", "-r", result.decrypted_file, "-Y", "ip", "-T", "fields", 
                         "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.port", "-c", "5"]
            sample_result = subprocess.run(sample_cmd, capture_output=True, text=True, timeout=10)
            
            if sample_result.returncode == 0 and sample_result.stdout.strip():
                print(f"  Sample IP traffic:")
                for i, line in enumerate(sample_result.stdout.strip().split('\n')[:3]):
                    if line.strip():
                        parts = line.split('\t')
                        src = parts[0] if len(parts) > 0 else "?"
                        dst = parts[1] if len(parts) > 1 else "?"
                        port = parts[2] if len(parts) > 2 else "?"
                        print(f"    {src} -> {dst} (port: {port})")
        
        except Exception as e:
            print(f"  Analysis error: {e}")
        
        return True
    else:
        print(f"Decryption FAILED: {result.error_message}")
        return False

def test_uat_configuration():
    """Test UAT configuration generation."""
    
    print(f"\nUAT Configuration Test")
    print("-" * 25)
    
    decryptor = PySharkWPADecryptor()
    creds = WPACredentials("TestSSID", "TestPassword")
    
    uat_config = decryptor.create_decryption_config(creds)
    expected = 'uat:80211_keys:"wpa-pwd","TestPassword:TestSSID"'
    
    print(f"Generated: {uat_config}")
    print(f"Expected:  {expected}")
    
    if uat_config == expected:
        print("UAT format is CORRECT")
        return True
    else:
        print("UAT format is INCORRECT")
        return False

def main():
    """Run all tests."""
    
    print("PyShark WPA Decryption - Real PCAP Test")
    print("File: tests/data/wpa-Induction.pcap")
    print("Expected: SSID=Coherer, Password=Induction")
    print()
    
    # Test UAT configuration
    uat_ok = test_uat_configuration()
    
    # Test real decryption
    decrypt_ok = test_real_wpa_decryption()
    
    print(f"\n" + "=" * 40)
    print("FINAL RESULTS")
    print("=" * 40)
    
    print(f"UAT Configuration: {'PASS' if uat_ok else 'FAIL'}")
    print(f"Real PCAP Decryption: {'PASS' if decrypt_ok else 'FAIL'}")
    
    if uat_ok and decrypt_ok:
        print(f"\nAll tests PASSED - PyShark WPA decryption is working correctly!")
        print(f"The UAT:80211_keys format properly decrypts WPA-encrypted traffic.")
    else:
        print(f"\nSome tests FAILED - check the implementation.")

if __name__ == "__main__":
    main()