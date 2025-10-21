#!/usr/bin/env python3
"""
Comprehensive WPA Decryption Test
=================================

This script tests WPA decryption by comparing encrypted vs decrypted packet analysis.
"""

import subprocess
import os
import tempfile

def analyze_encrypted_pcap():
    """Analyze the PCAP without decryption."""
    print("=" * 60)
    print("ANALYZING ENCRYPTED PCAP (No Credentials)")
    print("=" * 60)
    
    cmd = [
        "tshark", "-r", "tests/data/wpa-Induction.pcap",
        "-c", "10",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "wlan.fc.type_subtype", 
        "-e", "wlan.ssid",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.port",
        "-e", "http.host"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print("Command:", " ".join(cmd))
        print("\nRaw Output (first 10 packets):")
        print(result.stdout)
        
        # Count packets with IP data
        lines = result.stdout.strip().split('\n')
        ip_packets = 0
        for line in lines:
            fields = line.split('\t')
            if len(fields) >= 4 and fields[3]:  # Has IP source
                ip_packets += 1
        
        print(f"\nPackets with IP data (decrypted): {ip_packets}/{len(lines)}")
        return ip_packets
        
    except Exception as e:
        print(f"Error analyzing encrypted PCAP: {e}")
        return 0

def analyze_decrypted_pcap():
    """Analyze the PCAP with WPA decryption."""
    print("\n" + "=" * 60)
    print("ANALYZING DECRYPTED PCAP (With WPA Credentials)")
    print("=" * 60)
    
    # Create temporary decrypted file
    temp_fd, temp_file = tempfile.mkstemp(suffix='.pcap')
    os.close(temp_fd)
    
    try:
        # First, decrypt the PCAP file
        decrypt_cmd = [
            "tshark",
            "-r", "tests/data/wpa-Induction.pcap",
            "-w", temp_file,
            "-o", "wlan.enable_decryption:TRUE",
            "-o", 'uat:80211_keys:"wpa-pwd","Induction:Coherer"'
        ]
        
        print("Decryption Command:", " ".join(decrypt_cmd))
        
        decrypt_result = subprocess.run(decrypt_cmd, capture_output=True, text=True, timeout=30)
        
        if decrypt_result.returncode != 0:
            print(f"Decryption failed: {decrypt_result.stderr}")
            return 0
        
        # Check if decrypted file was created
        if not os.path.exists(temp_file) or os.path.getsize(temp_file) == 0:
            print("No decrypted output file created")
            return 0
        
        print(f"[OK] Decrypted file created: {os.path.getsize(temp_file)} bytes")
        
        # Now analyze the decrypted file
        analyze_cmd = [
            "tshark", "-r", temp_file,
            "-c", "10", 
            "-T", "fields",
            "-e", "frame.number",
            "-e", "wlan.fc.type_subtype",
            "-e", "wlan.ssid", 
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.port",
            "-e", "http.host"
        ]
        
        analyze_result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=30)
        print("\nAnalysis Command:", " ".join(analyze_cmd))
        print("\nDecrypted Output (first 10 packets):")
        print(analyze_result.stdout)
        
        # Count packets with IP data
        lines = analyze_result.stdout.strip().split('\n') if analyze_result.stdout.strip() else []
        ip_packets = 0
        for line in lines:
            fields = line.split('\t')
            if len(fields) >= 4 and fields[3]:  # Has IP source
                ip_packets += 1
        
        print(f"\nPackets with IP data (decrypted): {ip_packets}/{len(lines)}")
        return ip_packets
        
    except Exception as e:
        print(f"Error analyzing decrypted PCAP: {e}")
        return 0
    finally:
        # Cleanup
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass

def main():
    """Run the comprehensive WPA decryption test."""
    print("Comprehensive WPA Decryption Analysis")
    print("Testing with wpa-Induction.pcap")
    print("SSID: Coherer, Password: Induction")
    
    # Test 1: Analyze encrypted (should show no IP data)
    encrypted_ip_count = analyze_encrypted_pcap()
    
    # Test 2: Analyze decrypted (should show IP data)
    decrypted_ip_count = analyze_decrypted_pcap()
    
    # Summary
    print("\n" + "=" * 60)
    print("DECRYPTION TEST RESULTS")
    print("=" * 60)
    
    print(f"Encrypted PCAP - IP packets found: {encrypted_ip_count}")
    print(f"Decrypted PCAP - IP packets found: {decrypted_ip_count}")
    
    if decrypted_ip_count > encrypted_ip_count:
        print("\n[SUCCESS] WPA DECRYPTION WORKING!")
        print(f"   Successfully decrypted {decrypted_ip_count - encrypted_ip_count} additional IP packets")
        print("   This proves the UAT:80211_keys format is correctly decrypting WPA traffic")
    elif decrypted_ip_count == encrypted_ip_count and decrypted_ip_count > 0:
        print("\n[WARNING] DECRYPTION UNCERTAIN")
        print("   Same number of IP packets in both tests")
        print("   Either traffic was already decrypted or decryption didn't work")
    else:
        print("\n[FAIL] WPA DECRYPTION FAILED")
        print("   No additional IP packets found after decryption")
    
    # Test PyShark integration
    print(f"\n" + "=" * 60)
    print("PYSHARK INTEGRATION TEST")
    print("=" * 60)
    
    try:
        from tests.data.test_wpa_decryption import PySharkWPADecryptor, WPACredentials
        
        decryptor = PySharkWPADecryptor()
        credentials = WPACredentials("Coherer", "Induction", "Wireshark sample")
        
        uat_config = decryptor.create_decryption_config(credentials)
        expected = 'uat:80211_keys:"wpa-pwd","Induction:Coherer"'
        
        print(f"Generated UAT config: {uat_config}")
        print(f"Expected UAT config:  {expected}")
        
        if uat_config == expected:
            print("[OK] PyShark UAT generation is CORRECT")
        else:
            print("[FAIL] PyShark UAT generation is INCORRECT")
            
    except ImportError as e:
        print(f"[FAIL] PyShark module import failed: {e}")
    except Exception as e:
        print(f"[FAIL] PyShark test failed: {e}")

if __name__ == "__main__":
    main()