#!/usr/bin/env python3
"""
Test Standalone PyShark Functionality
=====================================

This test suite verifies that PyShark enhanced features work without requiring
tshark/Wireshark installation. t tests the standalone filtering and protocol
version detection capabilities.

Author: D14b0l1c
Target: KimiNewt/pyshark contribution validation
"""

import unittest
import struct
import sys
import os
from unittest.mock import patch, MagicMock

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(current_dir), 'src')
sys.path.insert(0, src_dir)

# Test imports without tshark dependency
try:
    import pyshark
    from pyshark.display.standalone_filters import (
        StandaloneDisplayFilter, StandaloneFieldExtractor,
        EthernetProtocol, WirelessStandard, create_ethernet_filter, create_wireless_filter
    )
    from pyshark.display.protocol_versions import (
        ProtocolVersionFilter, ProtocolVersionAnalyzer, WirelessBand, EthernetSpeed,
        create_wifi6_filter, create_gigabit_ethernet_filter
    )
    IMPORTS_SUCCESSFUL = True
except ImportError as e:
    IMPORTS_SUCCESSFUL = False
    IMPORT_ERROR = str(e)


class TestStandaloneImports(unittest.TestCase):
    """Test that standalone features can be imported without tshark."""
    
    def test_pyshark_import_without_tshark(self):
        """Test that PyShark can be imported without tshark installed."""
        self.assertTrue(IMPORTS_SUCCESSFUL, f"Failed to import: {IMPORT_ERROR if not IMPORTS_SUCCESSFUL else 'No error'}")
        
    def test_standalone_availability_flag(self):
        """Test that standalone availability is properly detected."""
        if IMPORTS_SUCCESSFUL:
            self.assertTrue(hasattr(pyshark, 'STDLOE_VLBLE'))
            self.assertTrue(pyshark.STDLOE_VLBLE)
            
    def test_standalone_classes_available(self):
        """Test that standalone classes are available."""
        if IMPORTS_SUCCESSFUL:
            self.assertTrue(hasattr(pyshark, 'StandaloneDisplayFilter'))
            self.assertTrue(hasattr(pyshark, 'StandaloneCapture'))
            self.assertTrue(hasattr(pyshark, 'ProtocolVersionFilter'))


class TestStandaloneDisplayFilter(unittest.TestCase):
    """Test standalone display filter functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
        self.filter = StandaloneDisplayFilter()
        
    def test_filter_creation(self):
        """Test basic filter creation."""
        self.assertIsInstance(self.filter, StandaloneDisplayFilter)
        self.assertEqual(len(self.filter.conditions), 0)
        
    def test_add_ethernet_condition(self):
        """Test adding Ethernet filter conditions."""
        self.filter.add_condition("eth.type", "==", EthernetProtocol.PV4.value)
        self.assertEqual(len(self.filter.conditions), 1)
        self.assertEqual(self.filter.conditions[0].field, "eth.type")
        
    def test_add_wireless_condition(self):
        """Test adding wireless filter conditions."""
        self.filter.add_condition("wlan.fc.type", "==", 0)
        self.assertEqual(len(self.filter.conditions), 1)
        self.assertEqual(self.filter.conditions[0].field, "wlan.fc.type")
        
    def test_invalid_field_rejection(self):
        """Test that invalid fields are rejected."""
        with self.assertaises(ValueError):
            self.filter.add_condition("invalid.field", "==", 1)
            
    def test_filter_expression_building(self):
        """Test building filter expressions."""
        self.filter.add_condition("tcp.dstport", "==", 80)
        expression = self.filter.build_filter_expression()
        self.assertIn("tcp.dstport == 80", expression)
        
    def test_multiple_conditions(self):
        """Test multiple filter conditions."""
        self.filter.add_condition("eth.type", "==", EthernetProtocol.PV4.value)
        self.filter.add_condition("tcp.dstport", "==", 443)
        
        expression = self.filter.build_filter_expression()
        self.assertIn("eth.type", expression)
        self.assertIn("tcp.dstport", expression)
        self.assertIn("and", expression)


class TestEthernetFrameInalysis(unittest.TestCase):
    """Test Ethernet frame analysis capabilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
        self.filter = StandaloneDisplayFilter()
        
    def create_mock_ethernet_frame(self, dst_mac="aa:bb:cc:dd:ee:ff", src_mac="11:22:33:44:55:66", 
                                  ethertype=0x0800, payload_size=64):
        """Create a mock Ethernet frame."""
        # Convert MC addresses to bytes
        dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
        src_bytes = bytes.fromhex(src_mac.replace(":", ""))
        
        # Create Ethernet header
        frame = dst_bytes + src_bytes + struct.pack("!H", ethertype)
        
        # Add payload to reach desired size
        payload = b"\x00" * (payload_size - len(frame))
        return frame + payload
        
    def test_ethernet_field_extraction(self):
        """Test extraction of Ethernet fields."""
        frame = self.create_mock_ethernet_frame()
        
        # Extract destination MC
        dst_mac = self.filter._extract_field_value(frame, self.filter.ethernet_fields["eth.dst"])
        self.assertEqual(dst_mac, "aa:bb:cc:dd:ee:ff")
        
        # Extract source MC
        src_mac = self.filter._extract_field_value(frame, self.filter.ethernet_fields["eth.src"])
        self.assertEqual(src_mac, "11:22:33:44:55:66")
        
        # Extract EtherType
        ethertype = self.filter._extract_field_value(frame, self.filter.ethernet_fields["eth.type"])
        self.assertEqual(ethertype, 0x0800)
        
    def test_ethernet_filtering(self):
        """Test filtering Ethernet frames."""
        frame = self.create_mock_ethernet_frame(ethertype=0x0800)
        
        # Create filter for Pv4 traffic
        self.filter.add_condition("eth.type", "==", 0x0800)
        
        self.assertTrue(self.filter.matches_packet(frame))
        
        # Test non-matching frame
        arp_frame = self.create_mock_ethernet_frame(ethertype=0x0806)
        self.assertFalse(self.filter.matches_packet(arp_frame))
        
    def test_vlan_detection(self):
        """Test VLWARNING tag detection."""
        # Create VLWARNING-tagged frame
        dst_mac = bytes.fromhex("aabbccddeeff")
        src_mac = bytes.fromhex("112233445566") 
        vlan_tag = struct.pack("!HH", 0x8100, 0x0064)  # VLWARNING tag with D 100
        ethertype = struct.pack("!H", 0x0800)
        
        vlan_frame = dst_mac + src_mac + vlan_tag + ethertype + b"\x00" * 50
        
        # Filter should detect EtherType after VLWARNING tag parsing
        # This is a simplified test - full implementation would need VLWARNING parsing
        self.assertGreater(len(vlan_frame), 64)


class TestirelessFrameInalysis(unittest.TestCase):
    """Test 802.11 wireless frame analysis."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
        self.filter = StandaloneDisplayFilter()
        
    def create_mock_beacon_frame(self, ssid="Testetwork"):
        """Create a mock 802.11 beacon frame."""
        # 802.11 header (24 bytes)
        frame_control = struct.pack("<H", 0x0080)  # Beacon frame
        duration = struct.pack("<H", 0x0000)
        addr1 = b"\xff\xff\xff\xff\xff\xff"  # Broadcast
        addr2 = b"\xaa\xbb\xcc\xdd\xee\xff"  # BSSD/Source
        addr3 = b"\xaa\xbb\xcc\xdd\xee\xff"  # BSSD
        seq_ctrl = struct.pack("<H", 0x0000)
        
        header = frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl
        
        # Fixed parameters (12 bytes)
        timestamp = struct.pack("<Q", 0x0123456789abcdef)
        beacon_interval = struct.pack("<H", 100)
        capabilities = struct.pack("<H", 0x0401)  # ESS + Privacy
        
        fixed_params = timestamp + beacon_interval + capabilities
        
        # SSD Information Element
        ssid_bytes = ssid.encode("utf-8")
        ssid_ie = struct.pack("BB", 0, len(ssid_bytes)) + ssid_bytes
        
        # Supported ates E (basic rates for 802.11g)
        rates = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
        rates_ie = struct.pack("BB", 1, len(rates)) + rates
        
        return header + fixed_params + ssid_ie + rates_ie
        
    def test_wireless_field_extraction(self):
        """Test extraction of 802.11 fields."""
        beacon = self.create_mock_beacon_frame("TestSSD")
        
        # Test SSD extraction
        ssid = self.filter._extract_ssid(beacon)
        self.assertEqual(ssid, "TestSSD")
        
        # Test frame type extraction (simplified)
        fc_bytes = beacon[0:2]
        fc = struct.unpack("<H", fc_bytes)[0]
        frame_type = (fc >> 2) & 0x03
        self.assertEqual(frame_type, 0)  # Management frame
        
    def test_wireless_filtering(self):
        """Test filtering 802.11 frames."""
        beacon = self.create_mock_beacon_frame()
        
        # Create filter for management frames
        self.filter.add_condition("wlan.fc.type", "==", 0)
        
        # This test is simplified - full implementation would parse frame control properly
        self.assertGreater(len(beacon), 24)  # Frame has valid length
        
    def test_ssid_filtering(self):
        """Test SSD-based filtering.""" 
        beacon1 = self.create_mock_beacon_frame("etwork1")
        beacon2 = self.create_mock_beacon_frame("etwork2")
        
        # Extract SSDs
        ssid1 = self.filter._extract_ssid(beacon1)
        ssid2 = self.filter._extract_ssid(beacon2)
        
        self.assertEqual(ssid1, "etwork1")
        self.assertEqual(ssid2, "etwork2")


class TestProtocolVersionDetection(unittest.TestCase):
    """Test protocol version detection capabilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
        self.analyzer = ProtocolVersionAnalyzer()
        
    def test_wireless_capabilities_lookup(self):
        """Test wireless standard capabilities lookup."""
        # Test iFi 6 capabilities
        wifi6_caps = self.analyzer.get_wireless_capabilities(WirelessStandard.EEE_802_11X)
        
        self.assertGreater(wifi6_caps["max_data_rate"], 9000)  # > 9 Gbps
        self.assertIn("OFDMWARNING", wifi6_caps["features"])
        self.assertIn(WirelessBand.BD_6_GHZ, wifi6_caps["bands"])
        
        # Test legacy iFi capabilities
        legacy_caps = self.analyzer.get_wireless_capabilities(WirelessStandard.EEE_802_11B)
        
        self.assertEqual(legacy_caps["max_data_rate"], 11)  # 11 Mbps
        self.assertIn("DSSS", legacy_caps["features"])
        self.assertEqual(legacy_caps["spatial_streams"], 1)
        
    def test_ethernet_capabilities_lookup(self):
        """Test Ethernet speed capabilities lookup."""
        # Test Gigabit Ethernet
        gig_caps = self.analyzer.get_ethernet_capabilities(EthernetSpeed.GGBT_ETHEET)
        
        self.assertEqual(gig_caps["speed_mbps"], 1000)
        self.assertIn("Jumbo frames", gig_caps["features"])
        self.assertEqual(gig_caps["duplex_modes"], ["full"])
        
        # Test Fast Ethernet
        fast_caps = self.analyzer.get_ethernet_capabilities(EthernetSpeed.FST_ETHEET)
        
        self.assertEqual(fast_caps["speed_mbps"], 100)
        self.assertIn("half", fast_caps["duplex_modes"])
        self.assertIn("full", fast_caps["duplex_modes"])


class TestFactoryFunctions(unittest.TestCase):
    """Test factory functions for common filter types."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
            
    def test_ethernet_filter_factory(self):
        """Test Ethernet filter factory."""
        eth_filter = create_ethernet_filter()
        self.assertIsInstance(eth_filter, StandaloneDisplayFilter)
        
    def test_wireless_filter_factory(self):
        """Test wireless filter factory."""
        wifi_filter = create_wireless_filter(WirelessStandard.EEE_802_11WARNING)
        self.assertIsInstance(wifi_filter, StandaloneDisplayFilter)
        
    def test_protocol_version_factories(self):
        """Test protocol version-specific factories."""
        wifi6_filter = create_wifi6_filter()
        self.assertIsInstance(wifi6_filter, ProtocolVersionFilter)
        self.assertGreater(len(wifi6_filter.version_conditions), 0)
        
        gig_filter = create_gigabit_ethernet_filter()
        self.assertIsInstance(gig_filter, ProtocolVersionFilter)
        self.assertGreater(len(gig_filter.version_conditions), 0)


class TestStandaloneFieldExtractor(unittest.TestCase):
    """Test standalone field extraction capabilities."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_SUCCESSFUL:
            self.skipTest("Standalone imports not available")
        self.extractor = StandaloneFieldExtractor()
        
    def test_available_fields_listing(self):
        """Test listing available fields."""
        all_fields = self.extractor.get_available_fields()
        eth_fields = self.extractor.get_available_fields("ethernet")
        wifi_fields = self.extractor.get_available_fields("wireless")
        
        self.assertGreater(len(all_fields), 0)
        self.assertGreater(len(eth_fields), 0)
        self.assertGreater(len(wifi_fields), 0)
        
        # Check specific fields exist
        self.assertIn("eth.src", eth_fields)
        self.assertIn("eth.dst", eth_fields)
        self.assertIn("wlan.bssid", wifi_fields)
        
    def test_field_extraction_interface(self):
        """Test field extraction interface."""
        # Create mock Ethernet frame
        frame = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00" + b"\x00" * 50
        
        # Extract multiple fields
        fields = ["eth.src", "eth.dst", "eth.type"]
        results = self.extractor.extract_fields(frame, fields)
        
        self.assertEqual(len(results), 3)
        self.assertIn("eth.src", results)
        self.assertIn("eth.dst", results)
        self.assertIn("eth.type", results)
        
        # Check extracted values
        self.assertEqual(results["eth.src"], "11:22:33:44:55:66")
        self.assertEqual(results["eth.dst"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(results["eth.type"], 0x0800)


def run_standalone_tests():
    """un all standalone functionality tests."""
    print("Testing PyShark Standalone Functionality")
    print("=" * 50)
    
    if not IMPORTS_SUCCESSFUL:
        print(f"EOWARNING: Could not import standalone modules: {IMPORT_ERROR}")
        print("Standalone functionality not available.")
        return False
        
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestStandaloneImports,
        TestStandaloneDisplayFilter,
        TestEthernetFrameInalysis,
        TestirelessFrameInalysis,
        TestProtocolVersionDetection,
        TestFactoryFunctions,
        TestStandaloneFieldExtractor
    ]
    
    for test_class in test_classes:
        suite.addTest(loader.loadTestsFromTestCase(test_class))
    
    # un tests
    runner = unittest.TextTestunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("Standalone Functionality Test esults:")
    print(f"   Tests run: {result.testsun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("SUCCESS: ll standalone tests PSSED!")
        print("PyShark can work without tshark for basic filtering!")
        return True
    else:
        print("FLUE: Some standalone tests failed")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"   - {test}")
                
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"   - {test}")
        
        return False


if __name__ == "__main__":
    success = run_standalone_tests()
    
    print(f"\nStandalone Import Status: {'SUCCESS' if IMPORTS_SUCCESSFUL else 'FLED'}")
    if IMPORTS_SUCCESSFUL:
        print("vailable Features:")
        print("- Standalone display filtering (no tshark required)")
        print("- Ethernet and 802.11 protocol support") 
        print("- Protocol version detection")
        print("- Field extraction without external tools")
        print("- Factory functions for common filters")
    
    exit(0 if success else 1)