#!/usr/bin/env python3
"""
Generate Ethernet Test PCAP for PyShark Display Filter Testing
================================================================

This script creates a test pcap file with various Ethernet frames
to validate the ethernet display filters in PyShark.

Dependencies: scapy
Usage: python generate_ethernet_test.py
Output: ethernet_test.pcap
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.dhcp import DHCP, BOOTP
import os

def create_ethernet_test_packets():
    """Create a variety of Ethernet test packets."""
    packets = []
    
    # Basic Ethernet frame with different types
    print("[OK] Creating basic Ethernet frames...")
    
    # 1. Simple TCP packet
    eth_tcp = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src="192.168.1.10", dst="192.168.1.1") / \
              TCP(sport=1234, dport=80, flags="S")
    packets.append(eth_tcp)
    
    # 2. UDP packet
    eth_udp = Ether(src="00:11:22:33:44:56", dst="aa:bb:cc:dd:ee:f0") / \
              IP(src="192.168.1.11", dst="192.168.1.1") / \
              UDP(sport=5678, dport=53)
    packets.append(eth_udp)
    
    # 3. ICMP packet
    eth_icmp = Ether(src="00:11:22:33:44:57", dst="aa:bb:cc:dd:ee:f1") / \
               IP(src="192.168.1.12", dst="8.8.8.8") / \
               ICMP(type=8, code=0)
    packets.append(eth_icmp)
    
    # 4. IPv6 packet
    eth_ipv6 = Ether(src="00:11:22:33:44:58", dst="aa:bb:cc:dd:ee:f2") / \
               IPv6(src="2001:db8::1", dst="2001:db8::2") / \
               TCP(sport=8080, dport=443)
    packets.append(eth_ipv6)
    
    # 5. ARP request
    arp_req = Ether(src="00:11:22:33:44:59", dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc="00:11:22:33:44:59", psrc="192.168.1.10",
                  hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
    packets.append(arp_req)
    
    # 6. ARP reply
    arp_reply = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:59") / \
                ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",
                    hwdst="00:11:22:33:44:59", pdst="192.168.1.10")
    packets.append(arp_reply)
    
    # VLAN tagged frames
    print("[OK] Creating VLAN tagged frames...")
    
    # 7. VLAN tagged TCP
    vlan_tcp = Ether(src="00:11:22:33:44:5a", dst="aa:bb:cc:dd:ee:f3") / \
               Dot1Q(vlan=100, prio=3) / \
               IP(src="192.168.100.10", dst="192.168.100.1") / \
               TCP(sport=2345, dport=443, flags="PA")
    packets.append(vlan_tcp)
    
    # 8. Double VLAN tagged
    double_vlan = Ether(src="00:11:22:33:44:5b", dst="aa:bb:cc:dd:ee:f4") / \
                  Dot1Q(vlan=200, prio=2) / \
                  Dot1Q(vlan=300, prio=1) / \
                  IP(src="192.168.200.10", dst="192.168.200.1") / \
                  UDP(sport=3456, dport=161)
    packets.append(double_vlan)
    
    # DHCP packets
    print("[OK] Creating DHCP packets...")
    
    # 9. DHCP Discover
    dhcp_discover = Ether(src="00:11:22:33:44:5c", dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr="00112233445c") / \
                    DHCP(options=[("message-type", "discover"), "end"])
    packets.append(dhcp_discover)
    
    # 10. DHCP Offer
    dhcp_offer = Ether(src="aa:bb:cc:dd:ee:f5", dst="00:11:22:33:44:5c") / \
                 IP(src="192.168.1.1", dst="192.168.1.100") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr="192.168.1.100", chaddr="00112233445c") / \
                 DHCP(options=[("message-type", "offer"), 
                              ("server_id", "192.168.1.1"),
                              ("lease_time", 86400), "end"])
    packets.append(dhcp_offer)
    
    # Large frames and fragmentation
    print("[OK] Creating jumbo and fragmented frames...")
    
    # 11. Large UDP payload (jumbo frame simulation)
    large_payload = "A" * 8000  # Large payload
    jumbo_frame = Ether(src="00:11:22:33:44:5d", dst="aa:bb:cc:dd:ee:f6") / \
                  IP(src="192.168.1.20", dst="192.168.1.21") / \
                  UDP(sport=9000, dport=9001) / large_payload
    packets.append(jumbo_frame)
    
    # Multicast and broadcast frames
    print("[OK] Creating multicast and broadcast frames...")
    
    # 12. IPv4 multicast
    multicast_ipv4 = Ether(src="00:11:22:33:44:5e", dst="01:00:5e:01:01:01") / \
                     IP(src="192.168.1.22", dst="224.1.1.1") / \
                     UDP(sport=5000, dport=5001) / "Multicast data"
    packets.append(multicast_ipv4)
    
    # 13. IPv6 multicast
    multicast_ipv6 = Ether(src="00:11:22:33:44:5f", dst="33:33:ff:01:01:01") / \
                     IPv6(src="2001:db8::10", dst="ff02::1") / \
                     UDP(sport=6000, dport=6001) / "IPv6 multicast"
    packets.append(multicast_ipv6)
    
    # Error and malformed frames
    print("[OK] Creating error frames...")
    
    # 14. Truncated frame (simulate using short payload)
    truncated = Ether(src="00:11:22:33:44:60", dst="aa:bb:cc:dd:ee:f7") / \
                IP(src="192.168.1.23", dst="192.168.1.24", len=100) / \
                TCP(sport=7000, dport=7001) / "Short"
    packets.append(truncated)
    
    # Different Ethernet types
    print("[OK] Creating different EtherType frames...")
    
    # 15. Custom EtherType
    custom_ether = Ether(src="00:11:22:33:44:61", dst="aa:bb:cc:dd:ee:f8", type=0x9000)
    packets.append(custom_ether)
    
    print(f"[OK] Generated {len(packets)} test packets")
    return packets

def main():
    """Generate the test PCAP file."""
    print("Generating Ethernet Test PCAP...")
    print("=" * 50)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate packets
    packets = create_ethernet_test_packets()
    
    # Write to PCAP file
    output_file = os.path.join(output_dir, "ethernet_test.pcap")
    wrpcap(output_file, packets)
    
    print("=" * 50)
    print(f"[OK] Test PCAP saved to: {output_file}")
    print(f"[OK] Total packets: {len(packets)}")
    print(f"[OK] File size: {os.path.getsize(output_file)} bytes")
    print("\nThis PCAP can be used to test PyShark Ethernet display filters!")

if __name__ == "__main__":
    main()