#!/usr/bin/env python3
"""
PyShark Encrypted Wireless Analysis Module
==========================================

This module provides WPA/WPA2 decryption capabilities combined with PyShark
display filters for comprehensive encrypted wireless traffic analysis.

Features:
- WPA/WPA2 PSK decryption using known credentials
- Integration with PyShark display filters
- Support for encrypted PCAP analysis
- Automated decryption and filtering workflows

Based on Wireshark's WPA decryption capabilities and enhanced with
PyShark display filter functionality.

Author: D14b0l1c
"""

import os
import sys
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Add PyShark source to path
current_dir = os.path.dirname(os.path.abspath(__file__))
pyshark_src = os.path.join(current_dir, "..", "..", "src")
sys.path.insert(0, pyshark_src)

try:
    from pyshark.display.wireless_filters import WirelessFilters, WirelessFilterType
    WIRELESS_FILTERS_AVAILABLE = True
except ImportError:
    WIRELESS_FILTERS_AVAILABLE = False


@dataclass
class WPACredentials:
    """WPA/WPA2 credentials for decryption."""
    ssid: str
    password: str
    description: str = ""


@dataclass 
class DecryptionResult:
    """Result of WPA decryption operation."""
    success: bool
    decrypted_file: Optional[str] = None
    packets_decrypted: int = 0
    error_message: str = ""


class PySharkWPADecryptor:
    """PyShark-based WPA/WPA2 decryption and analysis."""
    
    # Known WPA credentials for common test files
    KNOWN_CREDENTIALS = {
        "wpa-Induction.pcap": WPACredentials(
            ssid="Coherer", 
            password="Induction",
            description="Wireshark sample capture - WPA-PSK"
        ),
        # Add more known credentials here
        "example.pcap": WPACredentials(
            ssid="TestNetwork",
            password="testpassword", 
            description="Example credentials"
        )
    }
    
    def __init__(self, tshark_path: str = "tshark"):
        """Initialize the WPA decryptor.
        
        Args:
            tshark_path: Path to tshark executable (default: "tshark")
        """
        self.tshark_path = tshark_path
        self.temp_files = []
    
    def __del__(self):
        """Clean up temporary files."""
        self.cleanup()
    
    def cleanup(self):
        """Remove temporary files."""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
        self.temp_files.clear()
    
    def detect_credentials(self, pcap_file: str) -> Optional[WPACredentials]:
        """Auto-detect WPA credentials for known PCAP files.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            WPACredentials if known, None otherwise
        """
        filename = os.path.basename(pcap_file)
        return self.KNOWN_CREDENTIALS.get(filename)
    
    def create_decryption_config(self, credentials: WPACredentials) -> str:
        """Create Wireshark WPA decryption configuration.
        
        Args:
            credentials: WPA credentials
            
        Returns:
            Configuration string for tshark
        """
        # Format: uat:80211_keys:"wpa-pwd","password:ssid"
        return f'uat:80211_keys:"wpa-pwd","{credentials.password}:{credentials.ssid}"'
    
    def decrypt_pcap(self, 
                     input_pcap: str,
                     credentials: WPACredentials,
                     output_pcap: Optional[str] = None) -> DecryptionResult:
        """Decrypt WPA-encrypted PCAP file.
        
        Args:
            input_pcap: Path to encrypted PCAP file
            credentials: WPA credentials for decryption
            output_pcap: Optional output file (temp file if None)
            
        Returns:
            DecryptionResult with decryption status and output file
        """
        try:
            # Create output file
            if output_pcap is None:
                temp_fd, output_pcap = tempfile.mkstemp(suffix='.pcap')
                os.close(temp_fd)
                self.temp_files.append(output_pcap)
            
            # Create WPA configuration
            wpa_config = self.create_decryption_config(credentials)
            
            # Build tshark command for decryption
            tshark_cmd = [
                self.tshark_path,
                "-r", input_pcap,                    # Input file
                "-w", output_pcap,                   # Output file  
                "-o", "wlan.enable_decryption:TRUE", # Enable WPA decryption
                "-o", wpa_config,                    # WPA decryption keys
                "-Y", "wlan"                         # Only wireless frames
            ]
            
            print(f"Decrypting {input_pcap} with credentials:")
            print(f"  SSID: {credentials.ssid}")
            print(f"  Password: {credentials.password}")
            print(f"  Output: {output_pcap}")
            
            # Run tshark decryption
            result = subprocess.run(
                tshark_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return DecryptionResult(
                    success=False,
                    error_message=f"tshark failed: {result.stderr}"
                )
            
            # Verify output file exists and has content
            if not os.path.exists(output_pcap) or os.path.getsize(output_pcap) == 0:
                return DecryptionResult(
                    success=False,
                    error_message="No decrypted data produced"
                )
            
            # Count packets in decrypted file
            count_cmd = [self.tshark_path, "-r", output_pcap, "-c"]
            count_result = subprocess.run(count_cmd, capture_output=True, text=True)
            
            packet_count = 0
            if count_result.returncode == 0:
                try:
                    packet_count = len(count_result.stdout.strip().split('\n'))
                except:
                    packet_count = 0
            
            return DecryptionResult(
                success=True,
                decrypted_file=output_pcap,
                packets_decrypted=packet_count
            )
            
        except Exception as e:
            return DecryptionResult(
                success=False,
                error_message=f"Exception during decryption: {str(e)}"
            )
    
    def analyze_encrypted_pcap(self, 
                              pcap_file: str,
                              credentials: Optional[WPACredentials] = None) -> Dict:
        """Analyze encrypted PCAP with PyShark display filters.
        
        Args:
            pcap_file: Path to encrypted PCAP file
            credentials: Optional WPA credentials (auto-detected if None)
            
        Returns:
            Analysis results dictionary
        """
        results = {
            "file": pcap_file,
            "credentials_used": None,
            "decryption_success": False,
            "decrypted_file": None,
            "packets_total": 0,
            "packets_decrypted": 0,
            "filter_analysis": {},
            "error": None
        }
        
        try:
            # Auto-detect credentials if not provided
            if credentials is None:
                credentials = self.detect_credentials(pcap_file)
                if credentials is None:
                    results["error"] = "No credentials provided and none auto-detected"
                    return results
            
            results["credentials_used"] = {
                "ssid": credentials.ssid,
                "description": credentials.description
            }
            
            # Decrypt PCAP
            decrypt_result = self.decrypt_pcap(pcap_file, credentials)
            
            if not decrypt_result.success:
                results["error"] = decrypt_result.error_message
                return results
            
            results["decryption_success"] = True
            results["decrypted_file"] = decrypt_result.decrypted_file
            results["packets_decrypted"] = decrypt_result.packets_decrypted
            
            # Analyze with wireless display filters if available
            if WIRELESS_FILTERS_AVAILABLE:
                results["filter_analysis"] = self.analyze_with_filters(
                    decrypt_result.decrypted_file
                )
            else:
                results["filter_analysis"] = {
                    "error": "Wireless filters not available"
                }
            
            return results
            
        except Exception as e:
            results["error"] = f"Analysis failed: {str(e)}"
            return results
    
    def analyze_with_filters(self, decrypted_pcap: str) -> Dict:
        """Analyze decrypted PCAP with wireless display filters.
        
        Args:
            decrypted_pcap: Path to decrypted PCAP file
            
        Returns:
            Filter analysis results
        """
        try:
            filters = WirelessFilters.get_all_filters()
            
            analysis = {
                "total_filters": len(filters),
                "filter_results": {},
                "categories": {}
            }
            
            # Test key wireless filters
            key_filters = [
                "beacon_frames",
                "management_frames", 
                "data_frames",
                "probe_requests",
                "authentication_frames"
            ]
            
            for filter_name in key_filters:
                if filter_name in filters:
                    filter_obj = filters[filter_name]
                    
                    # Count packets matching filter using tshark
                    count = self.count_packets_with_filter(
                        decrypted_pcap, 
                        filter_obj.filter_expression
                    )
                    
                    analysis["filter_results"][filter_name] = {
                        "expression": filter_obj.filter_expression,
                        "packet_count": count,
                        "category": filter_obj.category.value
                    }
            
            # Analyze by category
            for category in WirelessFilterType:
                category_filters = WirelessFilters.get_filters_by_category(category)
                analysis["categories"][category.value] = len(category_filters)
            
            return analysis
            
        except Exception as e:
            return {"error": f"Filter analysis failed: {str(e)}"}
    
    def count_packets_with_filter(self, pcap_file: str, display_filter: str) -> int:
        """Count packets matching a display filter.
        
        Args:
            pcap_file: Path to PCAP file
            display_filter: Wireshark display filter expression
            
        Returns:
            Number of matching packets
        """
        try:
            cmd = [
                self.tshark_path,
                "-r", pcap_file,
                "-Y", display_filter,
                "-c"  # Count only
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                return len([line for line in lines if line.strip()])
            
            return 0
            
        except:
            return 0


def demonstrate_wpa_analysis():
    """Demonstrate WPA decryption and analysis with PyShark filters."""
    
    print("=" * 70)
    print("PyShark WPA/WPA2 Decryption and Display Filter Analysis")
    print("=" * 70)
    
    # Initialize decryptor
    decryptor = PySharkWPADecryptor()
    
    # Test file
    test_file = "wpa-Induction.pcap"
    
    if not os.path.exists(test_file):
        print(f"ERROR: Test file {test_file} not found")
        print("Please ensure the Wireshark sample capture is available")
        return False
    
    print(f"Analyzing encrypted PCAP: {test_file}")
    print()
    
    # Perform analysis
    results = decryptor.analyze_encrypted_pcap(test_file)
    
    # Display results
    print("Analysis Results:")
    print("-" * 30)
    
    if results["error"]:
        print(f"[ERROR] {results['error']}")
        return False
    
    print(f"[OK] File: {results['file']}")
    
    if results["credentials_used"]:
        creds = results["credentials_used"]
        print(f"[OK] SSID: {creds['ssid']}")
        print(f"[OK] Description: {creds['description']}")
    
    if results["decryption_success"]:
        print(f"[OK] Decryption: SUCCESS")
        print(f"[OK] Packets decrypted: {results['packets_decrypted']}")
        print(f"[OK] Decrypted file: {results['decrypted_file']}")
    else:
        print(f"[FAIL] Decryption failed")
        return False
    
    # Display filter analysis
    filter_analysis = results.get("filter_analysis", {})
    
    if "error" in filter_analysis:
        print(f"[WARN] Filter analysis: {filter_analysis['error']}")
    else:
        print(f"\nWireless Display Filter Analysis:")
        print(f"  Total filters available: {filter_analysis.get('total_filters', 0)}")
        
        filter_results = filter_analysis.get("filter_results", {})
        for filter_name, result in filter_results.items():
            count = result["packet_count"]
            expr = result["expression"]
            print(f"  {filter_name}: {count} packets ({expr})")
        
        categories = filter_analysis.get("categories", {})
        print(f"\nFilter Categories:")
        for cat_name, count in categories.items():
            print(f"  {cat_name}: {count} filters")
    
    # Cleanup
    decryptor.cleanup()
    
    print(f"\n[SUCCESS] WPA analysis complete!")
    return True


def main():
    """Main function for testing WPA decryption with PyShark."""
    
    try:
        success = demonstrate_wpa_analysis()
        return 0 if success else 1
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    exit(main())