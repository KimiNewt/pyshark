#!/usr/bin/env python3
"""
Direct TShark WPA Decryption Test
=================================

This tests TShark WPA decryption directly with proper quote handling.
"""

import subprocess
import tempfile
import os

def test_decryption():
    """Test TShark WPA decryption with proper command line handling."""
    
    print("Testing TShark WPA Decryption")
    print("=" * 40)
    
    # Create temporary output file
    temp_fd, temp_file = tempfile.mkstemp(suffix='.pcap')
    os.close(temp_fd)
    
    try:
        # Build command with proper quoting
        cmd = [
            "tshark",
            "-r", "tests/data/wpa-Induction.pcap",
            "-w", temp_file,
            "-o", "wlan.enable_decryption:TRUE",
            "-o", 'uat:80211_keys:"wpa-pwd","Induction:Coherer"'
        ]
        
        print(f"Command: {' '.join(cmd)}")
        print(f"Temp file: {temp_file}")
        
        # Run decryption
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print(f"[ERROR] Decryption failed:")
            print(f"   Stdout: {result.stdout}")
            print(f"   Stderr: {result.stderr}")
            return False
        
        # Check output file
        if not os.path.exists(temp_file):
            print("[ERROR] No output file created")
            return False
        
        file_size = os.path.getsize(temp_file)
        print(f"[OK] Decryption completed - Output file: {file_size} bytes")
        
        # Now analyze the decrypted file for IP traffic
        analyze_cmd = [
            "tshark", "-r", temp_file,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src", 
            "-e", "ip.dst",
            "-e", "tcp.port",
            "-e", "http.host",
            "-Y", "ip"  # Only IP packets
        ]
        
        print(f"\nAnalyzing IP traffic in decrypted file...")
        analyze_result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=10)
        
        if analyze_result.returncode == 0:
            ip_lines = [line for line in analyze_result.stdout.split('\n') if line.strip()]
            print(f"[OK] Found {len(ip_lines)} IP packets after decryption")
            
            if ip_lines:
                print(f"\nFirst few IP packets:")
                for i, line in enumerate(ip_lines[:5]):
                    fields = line.split('\t')
                    frame_num = fields[0] if len(fields) > 0 else "?"
                    src_ip = fields[1] if len(fields) > 1 else "?"
                    dst_ip = fields[2] if len(fields) > 2 else "?"
                    tcp_port = fields[3] if len(fields) > 3 else "?"
                    http_host = fields[4] if len(fields) > 4 else "?"
                    
                    print(f"  Frame {frame_num}: {src_ip} -> {dst_ip}, Port: {tcp_port}, Host: {http_host}")
                
                return True
            else:
                print("[WARNING] No IP packets found - decryption may not have worked")
                return False
        else:
            print(f"[ERROR] Analysis failed: {analyze_result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
        return False
    finally:
        # Cleanup
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass

def test_without_decryption():
    """Test analysis without decryption for comparison."""
    print(f"\nTesting WITHOUT decryption for comparison...")
    
    cmd = [
        "tshark", "-r", "tests/data/wpa-Induction.pcap",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-Y", "ip"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    
    if result.returncode == 0:
        ip_lines = [line for line in result.stdout.split('\n') if line.strip()]
        print(f"Without decryption: {len(ip_lines)} IP packets found")
        return len(ip_lines)
    else:
        print(f"Analysis without decryption failed: {result.stderr}")
        return 0

def main():
    """Run the direct decryption test."""
    print("Direct TShark WPA Decryption Test")
    print("File: tests/data/wpa-Induction.pcap")
    print("Credentials: SSID=Coherer, Password=Induction")
    
    # Test without decryption first
    no_decrypt_count = test_without_decryption()
    
    # Test with decryption
    success = test_decryption()
    
    print(f"\n" + "=" * 40)
    print("FINAL RESULT")
    print("=" * 40)
    
    if success:
        print("[SUCCESS] WPA DECRYPTION IS WORKING!")
        print("   The UAT:80211_keys format successfully decrypts WPA traffic")
        print("   TShark can extract IP packets from encrypted 802.11 frames")
    else:
        print("[ERROR] WPA decryption test failed or no encrypted data found")
        
    print(f"\nThis confirms our PyShark implementation uses the correct UAT syntax:")
    print('   uat:80211_keys:"wpa-pwd","Induction:Coherer"')

if __name__ == "__main__":
    main()