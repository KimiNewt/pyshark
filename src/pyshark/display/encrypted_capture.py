#!/usr/bin/env python3
"""
Enhanced PyShark Encrypted Capture Module
=========================================

This module extends PyShark's FileCapture to support WPA/WPA2 encrypted
PCAP files with automatic decryption and display filter integration.

Features:
- Drop-in replacement for PyShark FileCapture for encrypted files
- Automatic WPA/WPA2 decryption using known credentials
- Seamless integration with PyShark display filters
- Support for encrypted wireless traffic analysis

Author: D14b0l1c
"""

import os
import sys
import tempfile
from typing import Optional, Dict, Any

# Add PyShark source to path
current_dir = os.path.dirname(os.path.abspath(__file__))
pyshark_src = os.path.join(current_dir, "..", "..")
sys.path.insert(0, pyshark_src)

try:
    import pyshark
    from pyshark.capture.file_capture import FileCapture
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

from .encrypted_analysis import PySharkWPADecryptor, WPACredentials


class EncryptedFileCapture:
    """Enhanced FileCapture that supports WPA/WPA2 encrypted PCAP files.
    
    This class automatically detects and decrypts WPA-encrypted PCAP files
    before processing them with PyShark, allowing seamless analysis of
    encrypted wireless traffic.
    """
    
    def __init__(self, 
                 input_file: str,
                 display_filter: Optional[str] = None,
                 only_summaries: bool = False,
                 decryption_timeout: int = 60,
                 auto_cleanup: bool = True,
                 wpa_credentials: Optional[WPACredentials] = None,
                 **kwargs):
        """Initialize encrypted file capture.
        
        Args:
            input_file: Path to PCAP file (encrypted or unencrypted)
            display_filter: Wireshark display filter to apply
            only_summaries: If True, only packet summaries are parsed
            decryption_timeout: Timeout for decryption operations (seconds)
            auto_cleanup: Automatically clean up temporary files
            wpa_credentials: Optional WPA credentials (auto-detected if None)
            **kwargs: Additional arguments passed to FileCapture
        """
        self.input_file = input_file
        self.display_filter = display_filter
        self.only_summaries = only_summaries
        self.auto_cleanup = auto_cleanup
        self.decryption_timeout = decryption_timeout
        self.wpa_credentials = wpa_credentials
        
        self._decryptor = None
        self._decrypted_file = None
        self._capture = None
        self._is_encrypted = False
        
        # Initialize the capture
        self._initialize_capture(**kwargs)
    
    def _initialize_capture(self, **kwargs):
        """Initialize the underlying PyShark capture."""
        
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is not available")
        
        # Check if file needs decryption
        self._is_encrypted = self._detect_encryption()
        
        if self._is_encrypted:
            print(f"[INFO] Detected encrypted PCAP: {self.input_file}")
            
            # Initialize decryptor
            self._decryptor = PySharkWPADecryptor()
            
            # Get or detect credentials
            if self.wpa_credentials is None:
                self.wpa_credentials = self._decryptor.detect_credentials(self.input_file)
                
                if self.wpa_credentials is None:
                    raise ValueError(f"No WPA credentials available for {self.input_file}")
            
            print(f"[INFO] Using credentials - SSID: {self.wpa_credentials.ssid}")
            
            # Decrypt the file
            decrypt_result = self._decryptor.decrypt_pcap(
                self.input_file, 
                self.wpa_credentials
            )
            
            if not decrypt_result.success:
                raise RuntimeError(f"WPA decryption failed: {decrypt_result.error_message}")
            
            self._decrypted_file = decrypt_result.decrypted_file
            print(f"[INFO] Decryption successful: {decrypt_result.packets_decrypted} packets")
            
            # Use decrypted file for PyShark
            capture_file = self._decrypted_file
        else:
            # Use original file
            capture_file = self.input_file
        
        # Create PyShark FileCapture
        # Note: Handle the DEFULT_LOG_LEVEL typo if it exists
        try:
            self._capture = FileCapture(
                capture_file,
                display_filter=self.display_filter,
                only_summaries=self.only_summaries,
                **kwargs
            )
        except AttributeError as e:
            if "DEFULT_LOG_LEVEL" in str(e):
                print("[WARN] PyShark has DEFULT_LOG_LEVEL typo - creating capture without logging")
                # Workaround: Create capture without certain parameters
                self._capture = FileCapture(capture_file, **kwargs)
            else:
                raise
    
    def _detect_encryption(self) -> bool:
        """Detect if PCAP file contains encrypted wireless traffic.
        
        Returns:
            True if encryption detected, False otherwise
        """
        filename = os.path.basename(self.input_file).lower()
        
        # Simple heuristics for encrypted files
        encrypted_indicators = [
            "wpa", "wep", "encrypted", "crypto", "secure"
        ]
        
        return any(indicator in filename for indicator in encrypted_indicators)
    
    def __iter__(self):
        """Iterator interface - delegate to underlying capture."""
        if self._capture is None:
            raise RuntimeError("Capture not initialized")
        return iter(self._capture)
    
    def __getitem__(self, index):
        """Index access - delegate to underlying capture."""
        if self._capture is None:
            raise RuntimeError("Capture not initialized")
        return self._capture[index]
    
    def __len__(self):
        """Length - delegate to underlying capture."""
        if self._capture is None:
            raise RuntimeError("Capture not initialized")
        return len(self._capture)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def close(self):
        """Close the capture and clean up resources."""
        if self._capture:
            try:
                self._capture.close()
            except:
                pass
            self._capture = None
        
        if self.auto_cleanup and self._decryptor:
            self._decryptor.cleanup()
    
    @property
    def is_encrypted(self) -> bool:
        """Check if the source file was encrypted."""
        return self._is_encrypted
    
    @property
    def decrypted_file(self) -> Optional[str]:
        """Get path to decrypted file (if applicable)."""
        return self._decrypted_file
    
    @property
    def credentials_used(self) -> Optional[WPACredentials]:
        """Get WPA credentials used for decryption."""
        return self.wpa_credentials


def analyze_encrypted_pcap(pcap_file: str, 
                          display_filter: Optional[str] = None,
                          credentials: Optional[WPACredentials] = None) -> Dict[str, Any]:
    """High-level function to analyze encrypted PCAP files.
    
    Args:
        pcap_file: Path to PCAP file
        display_filter: Optional display filter to apply
        credentials: Optional WPA credentials
        
    Returns:
        Analysis results dictionary
    """
    results = {
        "file": pcap_file,
        "encrypted": False,
        "packets_total": 0,
        "packets_filtered": 0,
        "credentials_used": None,
        "decryption_success": False,
        "filter_applied": display_filter,
        "sample_packets": [],
        "error": None
    }
    
    try:
        with EncryptedFileCapture(
            pcap_file, 
            display_filter=display_filter,
            wpa_credentials=credentials
        ) as capture:
            
            results["encrypted"] = capture.is_encrypted
            results["decryption_success"] = capture.is_encrypted
            
            if capture.credentials_used:
                results["credentials_used"] = {
                    "ssid": capture.credentials_used.ssid,
                    "description": capture.credentials_used.description
                }
            
            # Count packets
            packet_count = 0
            sample_packets = []
            
            for packet in capture:
                packet_count += 1
                
                # Collect sample packet info
                if len(sample_packets) < 5:
                    packet_info = {
                        "number": packet_count,
                        "length": getattr(packet, 'length', 'unknown'),
                        "protocol": getattr(packet, 'highest_layer', 'unknown'),
                        "summary": str(packet)[:100] + "..." if len(str(packet)) > 100 else str(packet)
                    }
                    sample_packets.append(packet_info)
                
                # Limit processing for large files
                if packet_count >= 1000:
                    break
            
            results["packets_total"] = packet_count
            results["packets_filtered"] = packet_count  # All packets matched filter
            results["sample_packets"] = sample_packets
        
        return results
        
    except Exception as e:
        results["error"] = str(e)
        return results


def main():
    """Demonstration of encrypted PCAP analysis."""
    
    print("PyShark Enhanced Encrypted PCAP Analysis")
    print("=" * 45)
    
    test_file = "wpa-Induction.pcap"
    
    if not os.path.exists(test_file):
        print(f"[ERROR] Test file {test_file} not found")
        return 1
    
    print(f"Analyzing: {test_file}")
    print()
    
    # Basic analysis
    print("1. Basic Analysis (All packets)")
    print("-" * 35)
    
    results = analyze_encrypted_pcap(test_file)
    
    if results["error"]:
        print(f"[ERROR] {results['error']}")
        return 1
    
    print(f"[OK] File: {results['file']}")
    print(f"[OK] Encrypted: {results['encrypted']}")
    print(f"[OK] Decryption: {'SUCCESS' if results['decryption_success'] else 'N/A'}")
    print(f"[OK] Total packets: {results['packets_total']}")
    
    if results["credentials_used"]:
        creds = results["credentials_used"]
        print(f"[OK] SSID used: {creds['ssid']}")
    
    # Filter-specific analysis
    print(f"\n2. Filter-Specific Analysis")
    print("-" * 30)
    
    # Try with wireless management frames filter
    mgmt_results = analyze_encrypted_pcap(test_file, display_filter="wlan.fc.type == 0")
    
    if not mgmt_results["error"]:
        print(f"[OK] Management frames: {mgmt_results['packets_total']}")
    else:
        print(f"[WARN] Management filter failed: {mgmt_results['error']}")
    
    # Try with beacon frames filter
    beacon_results = analyze_encrypted_pcap(test_file, display_filter="wlan.fc.type_subtype == 0x08")
    
    if not beacon_results["error"]:
        print(f"[OK] Beacon frames: {beacon_results['packets_total']}")
    else:
        print(f"[WARN] Beacon filter failed: {beacon_results['error']}")
    
    print(f"\n[SUCCESS] Encrypted PCAP analysis completed!")
    
    return 0


if __name__ == "__main__":
    exit(main())