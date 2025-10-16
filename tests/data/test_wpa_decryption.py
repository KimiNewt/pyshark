#!/usr/bin/env python3
"""
Test WPA Decryption with PyShark Display Filters
================================================

This script demonstrates the integration of WPA/WPA2 decryption with
PyShark display filters using the Wireshark sample capture.

Test File: wpa-Induction.pcap
- SSID: "Coherer" 
- Password: "Induction"
- Source: Wireshark Sample Captures
"""

import os
import sys

def setup_environment():
    """Setup the Python environment."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pyshark_src = os.path.join(current_dir, "..", "..", "src")
    sys.path.insert(0, pyshark_src)

def test_wpa_decryption():
    """Test WPA decryption and filtering."""
    
    print("Testing WPA Decryption with PyShark Display Filters")
    print("=" * 55)
    
    try:
        # Import our new encrypted analysis module
        from pyshark.display.encrypted_analysis import PySharkWPADecryptor, WPACredentials
        
        print("[OK] Imported encrypted analysis module")
        
        # Check test file
        test_file = "wpa-Induction.pcap"
        if not os.path.exists(test_file):
            print(f"[ERROR] Test file {test_file} not found")
            return False
        
        file_size = os.path.getsize(test_file)
        print(f"[OK] Test file: {test_file} ({file_size} bytes)")
        
        # Initialize decryptor
        decryptor = PySharkWPADecryptor()
        print("[OK] Initialized WPA decryptor")
        
        # Test credential detection
        auto_creds = decryptor.detect_credentials(test_file)
        if auto_creds:
            print(f"[OK] Auto-detected credentials:")
            print(f"     SSID: {auto_creds.ssid}")
            print(f"     Password: {auto_creds.password}")
            print(f"     Description: {auto_creds.description}")
        else:
            print("[WARN] No auto-detected credentials")
            # Manual credentials as fallback
            auto_creds = WPACredentials(
                ssid="Coherer",
                password="Induction", 
                description="Manual fallback"
            )
        
        # Test decryption
        print(f"\nTesting WPA Decryption...")
        print("-" * 30)
        
        decrypt_result = decryptor.decrypt_pcap(test_file, auto_creds)
        
        if decrypt_result.success:
            print(f"[OK] Decryption successful!")
            print(f"     Decrypted file: {decrypt_result.decrypted_file}")
            print(f"     Packets processed: {decrypt_result.packets_decrypted}")
        else:
            print(f"[ERROR] Decryption failed: {decrypt_result.error_message}")
            return False
        
        # Test full analysis
        print(f"\nTesting Full Analysis...")
        print("-" * 25)
        
        analysis_results = decryptor.analyze_encrypted_pcap(test_file)
        
        if analysis_results["error"]:
            print(f"[ERROR] Analysis failed: {analysis_results['error']}")
            return False
        
        print(f"[OK] Analysis completed successfully")
        
        # Display results
        if analysis_results["decryption_success"]:
            print(f"     Packets decrypted: {analysis_results['packets_decrypted']}")
        
        filter_analysis = analysis_results.get("filter_analysis", {})
        if "error" not in filter_analysis:
            total_filters = filter_analysis.get("total_filters", 0)
            print(f"     Wireless filters available: {total_filters}")
            
            filter_results = filter_analysis.get("filter_results", {})
            if filter_results:
                print(f"     Filter test results:")
                for filter_name, result in filter_results.items():
                    count = result["packet_count"]
                    print(f"       {filter_name}: {count} packets")
        
        # Cleanup
        decryptor.cleanup()
        print(f"\n[OK] Cleanup completed")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integration_with_existing_filters():
    """Test integration with existing wireless filters."""
    
    print(f"\nTesting Integration with Existing Wireless Filters")
    print("-" * 50)
    
    try:
        from pyshark.display.wireless_filters import WirelessFilters
        
        filters = WirelessFilters.get_all_filters()
        print(f"[OK] Loaded {len(filters)} wireless filters")
        
        # Test some key filters for encrypted analysis
        encryption_relevant_filters = [
            "wlan_frames", 
            "beacon_frames",
            "management_frames",
            "data_frames",
            "authentication_frames"
        ]
        
        print(f"[OK] Key filters for encrypted analysis:")
        
        for filter_name in encryption_relevant_filters:
            if filter_name in filters:
                filter_obj = filters[filter_name]
                print(f"     {filter_name}: {filter_obj.filter_expression}")
            else:
                print(f"     {filter_name}: [NOT FOUND]")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Integration test failed: {e}")
        return False

def main():
    """Main test function."""
    
    print("PyShark WPA Decryption Integration Tests")
    print("=" * 45)
    print()
    
    # Setup
    setup_environment()
    
    # Run tests
    tests = [
        ("WPA Decryption", test_wpa_decryption),
        ("Filter Integration", test_integration_with_existing_filters)
    ]
    
    passed = 0
    
    for test_name, test_func in tests:
        print(f"Running {test_name} test...")
        if test_func():
            print(f"[OK] {test_name}: PASSED")
            passed += 1
        else:
            print(f"[FAIL] {test_name}: FAILED")
        print()
    
    # Summary
    print("=" * 45)
    print(f"Test Results: {passed}/{len(tests)} passed")
    
    if passed == len(tests):
        print("[SUCCESS] All tests passed!")
        print("\nWPA decryption integration is working!")
        print("\nUsage:")
        print("  from pyshark.display.encrypted_analysis import PySharkWPADecryptor")
        print("  decryptor = PySharkWPADecryptor()")
        print("  results = decryptor.analyze_encrypted_pcap('wpa-Induction.pcap')")
    else:
        print(f"[FAIL] {len(tests) - passed} tests failed")
    
    return passed == len(tests)

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)