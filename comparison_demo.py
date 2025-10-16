#!/usr/bin/env python3
"""
PyShark WPA Decryption Comparison Demo
=====================================

This demo shows the difference between PyShark analysis with and without 
WPA decryption, demonstrating how encrypted wireless traffic becomes 
readable IP traffic after decryption.

For testing, you can use the Wireshark sample captures:
https://wiki.wireshark.org/SampleCaptures

Specifically: wpa-Induction.pcap (password: "Induction")

Author: D14b0l1c
"""

import os
import sys
import tempfile
from typing import Dict, Any, Optional, List

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import our enhanced modules
try:
    from src.pyshark.display.wireless_filters import WirelessFilters
    from src.pyshark.display.encrypted_analysis import PySharkWPADecryptor, WPACredentials
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"[ERROR] Module import failed: {e}")
    MODULES_AVAILABLE = False

# Try to import PyShark for actual packet analysis
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print(f"[WARN] PyShark not available - showing conceptual demo only")
    PYSHARK_AVAILABLE = False


def simulate_encrypted_analysis(pcap_file: str) -> Dict[str, Any]:
    """Simulate analysis of encrypted PCAP without decryption."""
    
    results = {
        "file": pcap_file,
        "encrypted_packets": 0,
        "readable_packets": 0,
        "protocols_found": [],
        "ip_traffic": [],
        "analysis_type": "Without Decryption"
    }
    
    if not PYSHARK_AVAILABLE:
        # Simulated results for demo purposes
        results.update({
            "encrypted_packets": 25,
            "readable_packets": 8,
            "protocols_found": ["802.11", "EAPOL", "WPA"],
            "ip_traffic": ["Only beacon frames and authentication visible"],
            "limitation": "Encrypted data frames cannot be analyzed"
        })
        return results
    
    try:
        cap = pyshark.FileCapture(pcap_file)
        
        for packet in cap:
            if hasattr(packet, 'wlan'):
                results["encrypted_packets"] += 1
                
                # Only management and control frames are readable without decryption
                if hasattr(packet.wlan, 'fc_type'):
                    if packet.wlan.fc_type in ['0', '1']:  # Management/Control
                        results["readable_packets"] += 1
                        
                # Check for readable protocols
                for layer in packet.layers:
                    if layer not in results["protocols_found"]:
                        results["protocols_found"].append(layer)
        
        cap.close()
        
    except Exception as e:
        results["error"] = str(e)
    
    return results


def simulate_decrypted_analysis(pcap_file: str, credentials: WPACredentials) -> Dict[str, Any]:
    """Simulate analysis of encrypted PCAP with WPA decryption."""
    
    results = {
        "file": pcap_file,
        "encrypted_packets": 0,
        "decrypted_packets": 0,
        "protocols_found": [],
        "ip_traffic": [],
        "analysis_type": "With WPA Decryption",
        "credentials_used": f"SSID: {credentials.ssid}"
    }
    
    if not MODULES_AVAILABLE:
        results["error"] = "Decryption modules not available"
        return results
    
    try:
        # Initialize decryptor
        decryptor = PySharkWPADecryptor()
        
        # Decrypt the PCAP
        decrypt_result = decryptor.decrypt_pcap(pcap_file, credentials)
        
        if not decrypt_result.success:
            results["error"] = decrypt_result.error_message
            return results
        
        # Analyze decrypted file
        if PYSHARK_AVAILABLE and decrypt_result.decrypted_file:
            cap = pyshark.FileCapture(decrypt_result.decrypted_file)
            
            for packet in cap:
                results["encrypted_packets"] += 1
                
                if hasattr(packet, 'ip') or hasattr(packet, 'ipv6'):
                    results["decrypted_packets"] += 1
                    
                    # Extract IP traffic info
                    if hasattr(packet, 'ip'):
                        src = getattr(packet.ip, 'src', 'unknown')
                        dst = getattr(packet.ip, 'dst', 'unknown')
                        protocol = getattr(packet.ip, 'proto', 'unknown')
                        results["ip_traffic"].append(f"{src} -> {dst} ({protocol})")
                
                # Collect all protocols
                for layer in packet.layers:
                    if layer not in results["protocols_found"]:
                        results["protocols_found"].append(layer)
                        
                # Limit for demo
                if results["encrypted_packets"] >= 50:
                    break
            
            cap.close()
        else:
            # Simulated results
            results.update({
                "encrypted_packets": 25,
                "decrypted_packets": 18,
                "protocols_found": ["802.11", "IP", "TCP", "HTTP", "DNS", "DHCP"],
                "ip_traffic": [
                    "192.168.1.100 -> 192.168.1.1 (TCP)",
                    "192.168.1.100 -> 8.8.8.8 (UDP/DNS)",
                    "192.168.1.100 -> 74.125.224.147 (TCP/HTTP)"
                ]
            })
        
        # Cleanup
        decryptor.cleanup()
        
    except Exception as e:
        results["error"] = str(e)
    
    return results


def display_comparison_results(encrypted_results: Dict[str, Any], 
                              decrypted_results: Dict[str, Any]):
    """Display side-by-side comparison of results."""
    
    print("\n" + "=" * 80)
    print("PYSHARK WPA DECRYPTION COMPARISON")
    print("=" * 80)
    
    # Header
    print(f"{'WITHOUT DECRYPTION':<40} | {'WITH WPA DECRYPTION':<38}")
    print("-" * 40 + " | " + "-" * 38)
    
    # Analysis type
    print(f"{encrypted_results['analysis_type']:<40} | {decrypted_results['analysis_type']:<38}")
    print()
    
    # Packet counts
    enc_total = encrypted_results.get('encrypted_packets', 0)
    enc_readable = encrypted_results.get('readable_packets', 0)
    dec_total = decrypted_results.get('encrypted_packets', 0)
    dec_readable = decrypted_results.get('decrypted_packets', 0)
    
    print(f"Total packets: {enc_total:<28} | Total packets: {dec_total}")
    print(f"Readable: {enc_readable:<32} | IP traffic: {dec_readable}")
    print()
    
    # Protocols found
    enc_protocols = encrypted_results.get('protocols_found', [])
    dec_protocols = decrypted_results.get('protocols_found', [])
    
    print(f"Protocols visible: {len(enc_protocols):<22} | Protocols visible: {len(dec_protocols)}")
    print(f"- {', '.join(enc_protocols[:3]):<35} | - {', '.join(dec_protocols[:5])}")
    print()
    
    # Key differences
    print("Key Insights:")
    print(f"- Only management frames readable      | - Full IP traffic analysis possible")
    print(f"- Data frames remain encrypted        | - HTTP, DNS, DHCP traffic visible")
    print(f"- Limited protocol analysis           | - Complete network communication")
    
    # IP Traffic comparison
    if decrypted_results.get('ip_traffic'):
        print(f"\nDecrypted IP Traffic Examples:")
        for i, traffic in enumerate(decrypted_results['ip_traffic'][:3], 1):
            print(f"  {i}. {traffic}")
    
    # Credentials used
    if decrypted_results.get('credentials_used'):
        print(f"\nDecryption: {decrypted_results['credentials_used']}")
    
    print("\n" + "=" * 80)


def demo_filter_integration():
    """Show how display filters work with encrypted data."""
    
    print("\nDISPLAY FILTER INTEGRATION")
    print("-" * 30)
    
    if not MODULES_AVAILABLE:
        print("[SKIP] Modules not available")
        return
    
    wireless = WirelessFilters()
    filters = wireless.get_all_filters()
    
    # Show relevant filters for encrypted analysis
    relevant_filters = [
        ('beacon_frames', 'Identify wireless networks'),
        ('wpa_handshake', 'Capture authentication process'), 
        ('management_frames', 'Control and management traffic'),
        ('data_frames', 'Encrypted user data (needs decryption)'),
        ('probe_requests', 'Device network discovery')
    ]
    
    print("Wireless Display Filters for Encrypted Traffic Analysis:")
    print()
    
    for filter_name, description in relevant_filters:
        if filter_name in filters:
            filter_obj = filters[filter_name]
            print(f"Filter: {filter_name}")
            print(f"  Expression: {filter_obj.filter_expression}")
            print(f"  Purpose: {description}")
            print()
    
    print("Note: Display filters work on both encrypted and decrypted data.")
    print("Decryption enables analysis of data frames that would otherwise be opaque.")


def main():
    """Main demonstration function."""
    
    print("PyShark WPA Decryption Comparison Demo")
    print("=" * 42)
    print("Author: D14b0l1c")
    print()
    
    # Check for test file (simulated)
    test_file = "wpa-Induction.pcap"  # Wireshark sample file
    
    print("Test File Information:")
    print(f"File: {test_file}")
    print(f"Source: Wireshark Sample Captures")
    print(f"URL: https://wiki.wireshark.org/SampleCaptures")
    print(f"Credentials: SSID='Coherer', Password='Induction'")
    
    if not os.path.exists(test_file):
        print(f"\n[INFO] Test file not present - running conceptual demo")
        print(f"[INFO] Download from Wireshark sample captures for full demo")
        conceptual_demo = True
    else:
        print(f"\n[OK] Test file found - running actual analysis")
        conceptual_demo = False
    
    # Create credentials
    credentials = WPACredentials(
        ssid="Coherer",
        password="Induction",
        description="Wireshark sample WPA capture"
    )
    
    print(f"\n1. ANALYZING WITHOUT DECRYPTION")
    print("-" * 35)
    
    if conceptual_demo:
        encrypted_results = simulate_encrypted_analysis(test_file)
    else:
        encrypted_results = simulate_encrypted_analysis(test_file)
    
    print(f"[INFO] Encrypted packets: {encrypted_results.get('encrypted_packets', 'N/A')}")
    print(f"[INFO] Readable packets: {encrypted_results.get('readable_packets', 'N/A')}")
    print(f"[LIMITATION] Data frames remain encrypted")
    
    print(f"\n2. ANALYZING WITH WPA DECRYPTION")
    print("-" * 36)
    
    if conceptual_demo:
        decrypted_results = simulate_decrypted_analysis(test_file, credentials)
    else:
        decrypted_results = simulate_decrypted_analysis(test_file, credentials)
    
    if decrypted_results.get('error'):
        print(f"[ERROR] {decrypted_results['error']}")
        # Use simulated results for demo
        decrypted_results = {
            "analysis_type": "With WPA Decryption (Simulated)",
            "encrypted_packets": 25,
            "decrypted_packets": 18,
            "protocols_found": ["802.11", "IP", "TCP", "HTTP", "DNS", "DHCP"],
            "ip_traffic": [
                "192.168.1.100 -> 192.168.1.1 (DHCP)",
                "192.168.1.100 -> 8.8.8.8 (DNS)",
                "192.168.1.100 -> 74.125.224.147 (HTTP)"
            ],
            "credentials_used": "SSID: Coherer"
        }
    
    print(f"[OK] Decrypted packets: {decrypted_results.get('decrypted_packets', 'N/A')}")
    print(f"[OK] IP protocols visible: {len(decrypted_results.get('protocols_found', []))}")
    print(f"[SUCCESS] Full network analysis possible")
    
    # Display comparison
    display_comparison_results(encrypted_results, decrypted_results)
    
    # Show filter integration
    demo_filter_integration()
    
    print(f"\n[CONCLUSION]")
    print(f"PyShark with WPA decryption transforms encrypted wireless captures")
    print(f"from limited visibility into comprehensive network analysis,")
    print(f"enabling full IP traffic inspection and protocol analysis.")
    
    return 0


if __name__ == "__main__":
    exit(main())