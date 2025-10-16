#!/usr/bin/env python3
"""
Generate Wireless Test PCAP for PyShark Display Filter Testing
===============================================================

This script creates a test pcap file with various Wireless (802.11) frames
to validate the wireless display filters in PyShark.

Dependencies: scapy
Usage: python generate_wireless_test.py
Output: wireless_test.pcap
"""

from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import LLC, SNAP
import os

def create_wireless_test_packets():
    """Create a variety of 802.11 test packets."""
    packets = []
    
    # Management frames
    print("[OK] Creating 802.11 management frames...")
    
    # 1. Beacon frame
    beacon = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                   addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
             Dot11Beacon(cap=0x1234) / \
             Dot11Elt(ID="SSID", info="TestNetwork") / \
             Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")
    packets.append(beacon)
    
    # 2. Probe request
    probe_req = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="ff:ff:ff:ff:ff:ff") / \
                Dot11ProbeReq() / \
                Dot11Elt(ID="SSID", info="") / \
                Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96")
    packets.append(probe_req)
    
    # 3. Probe response
    probe_resp = Dot11(type=0, subtype=5, addr1="aa:bb:cc:dd:ee:ff",
                       addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
                 Dot11ProbeResp(cap=0x1234) / \
                 Dot11Elt(ID="SSID", info="TestNetwork") / \
                 Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")
    packets.append(probe_resp)
    
    # 4. Authentication frame
    auth = Dot11(type=0, subtype=11, addr1="00:11:22:33:44:55",
                 addr2="aa:bb:cc:dd:ee:ff", addr3="00:11:22:33:44:55") / \
           Dot11Auth(algo=0, seqnum=1, status=0)
    packets.append(auth)
    
    # 5. Association request
    assoc_req = Dot11(type=0, subtype=0, addr1="00:11:22:33:44:55",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="00:11:22:33:44:55") / \
                Dot11AssoReq(cap=0x1234) / \
                Dot11Elt(ID="SSID", info="TestNetwork") / \
                Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96")
    packets.append(assoc_req)
    
    # 6. Association response
    assoc_resp = Dot11(type=0, subtype=1, addr1="aa:bb:cc:dd:ee:ff",
                       addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
                 Dot11AssoResp(cap=0x1234, status=0, AID=1) / \
                 Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")
    packets.append(assoc_resp)
    
    # 7. Disassociation
    disassoc = Dot11(type=0, subtype=10, addr1="aa:bb:cc:dd:ee:ff",
                     addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
               Dot11Disas(reason=3)
    packets.append(disassoc)
    
    # 8. Deauthentication
    deauth = Dot11(type=0, subtype=12, addr1="aa:bb:cc:dd:ee:ff",
                   addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") / \
             Dot11Deauth(reason=2)
    packets.append(deauth)
    
    # Control frames
    print("[OK] Creating 802.11 control frames...")
    
    # 9. RTS (Request to Send)
    rts = Dot11(type=1, subtype=11, addr1="00:11:22:33:44:55",
                addr2="aa:bb:cc:dd:ee:ff")
    packets.append(rts)
    
    # 10. CTS (Clear to Send)
    cts = Dot11(type=1, subtype=12, addr1="aa:bb:cc:dd:ee:ff")
    packets.append(cts)
    
    # 11. ACK
    ack = Dot11(type=1, subtype=13, addr1="aa:bb:cc:dd:ee:ff")
    packets.append(ack)
    
    # Data frames
    print("[OK] Creating 802.11 data frames...")
    
    # 12. Basic data frame with IP
    data_ip = Dot11(type=2, subtype=0, addr1="00:11:22:33:44:55",
                    addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
              LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
              SNAP(OUI=0, code=0x0800) / \
              IP(src="192.168.1.100", dst="192.168.1.1") / \
              TCP(sport=1234, dport=80) / "HTTP GET request"
    packets.append(data_ip)
    
    # 13. QoS data frame
    qos_data = Dot11(type=2, subtype=8, addr1="00:11:22:33:44:55",
                     addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
               Dot11QoS(TID=5, EOSP=0, Ack_Policy=0, Reserved=0) / \
               LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
               SNAP(OUI=0, code=0x0800) / \
               IP(src="192.168.1.101", dst="192.168.1.1") / \
               UDP(sport=5678, dport=53) / "DNS query"
    packets.append(qos_data)
    
    # 14. Null data frame
    null_data = Dot11(type=2, subtype=4, addr1="00:11:22:33:44:55",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00")
    packets.append(null_data)
    
    # 15. QoS Null data frame
    qos_null = Dot11(type=2, subtype=12, addr1="00:11:22:33:44:55",
                     addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
               Dot11QoS(TID=0)
    packets.append(qos_null)
    
    # WEP encrypted frames
    print("[OK] Creating WEP encrypted frames...")
    
    # 16. WEP encrypted data
    wep_data = Dot11(type=2, subtype=0, FCfield=0x40, addr1="00:11:22:33:44:55",
                     addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
               Dot11WEP(iv="123456", keyid=0, wepdata="encrypted_payload_here")
    packets.append(wep_data)
    
    # WPA encrypted frames (simulated)
    print("[OK] Creating WPA encrypted frames...")
    
    # 17. WPA encrypted data
    wpa_data = Dot11(type=2, subtype=0, FCfield=0x40, addr1="00:11:22:33:44:55",
                     addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
               Raw("encrypted_wpa_data_simulation")
    packets.append(wpa_data)
    
    # 18. EAPOL frames (WPA handshake simulation)
    eapol = Dot11(type=2, subtype=0, addr1="00:11:22:33:44:55",
                  addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
            SNAP(OUI=0, code=0x888e) / \
            Raw("eapol_key_exchange_data")
    packets.append(eapol)
    
    # Different addressing modes
    print("[OK] Creating frames with different addressing...")
    
    # 19. ToDS frame
    to_ds = Dot11(type=2, subtype=0, FCfield=0x01, addr1="00:11:22:33:44:55",
                  addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
            SNAP(OUI=0, code=0x0800) / \
            IP(src="192.168.1.102", dst="192.168.1.1") / \
            ICMP(type=8)
    packets.append(to_ds)
    
    # 20. FromDS frame
    from_ds = Dot11(type=2, subtype=0, FCfield=0x02, addr1="aa:bb:cc:dd:ee:ff",
                    addr2="00:11:22:33:44:55", addr3="bb:cc:dd:ee:ff:00") / \
              LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
              SNAP(OUI=0, code=0x0800) / \
              IP(src="192.168.1.1", dst="192.168.1.102") / \
              ICMP(type=0)
    packets.append(from_ds)
    
    # 21. WDS (4-address) frame
    wds = Dot11(type=2, subtype=0, FCfield=0x03, addr1="00:11:22:33:44:55",
                addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00",
                addr4="cc:dd:ee:ff:00:11") / \
          LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
          SNAP(OUI=0, code=0x0800) / \
          IP(src="192.168.1.103", dst="192.168.1.104") / \
          UDP(sport=8000, dport=8001)
    packets.append(wds)
    
    # Different data subtypes
    print("[OK] Creating special data frames...")
    
    # 22. Data + CF-ACK
    data_cfack = Dot11(type=2, subtype=1, addr1="00:11:22:33:44:55",
                       addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
                 LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                 SNAP(OUI=0, code=0x0800) / \
                 IP(src="192.168.1.105", dst="192.168.1.1") / \
                 TCP(sport=9000, dport=443)
    packets.append(data_cfack)
    
    # IPv6 over 802.11
    print("[OK] Creating IPv6 over 802.11...")
    
    # 23. IPv6 data frame
    ipv6_data = Dot11(type=2, subtype=0, addr1="00:11:22:33:44:55",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                SNAP(OUI=0, code=0x86dd) / \
                IPv6(src="2001:db8::100", dst="2001:db8::1") / \
                TCP(sport=2000, dport=80)
    packets.append(ipv6_data)
    
    # Multicast and broadcast
    print("[OK] Creating multicast and broadcast frames...")
    
    # 24. Broadcast data
    broadcast = Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                SNAP(OUI=0, code=0x0800) / \
                IP(src="192.168.1.106", dst="255.255.255.255") / \
                UDP(sport=68, dport=67)
    packets.append(broadcast)
    
    # 25. Multicast data
    multicast = Dot11(type=2, subtype=0, addr1="01:00:5e:01:01:01",
                      addr2="aa:bb:cc:dd:ee:ff", addr3="bb:cc:dd:ee:ff:00") / \
                LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
                SNAP(OUI=0, code=0x0800) / \
                IP(src="192.168.1.107", dst="224.1.1.1") / \
                UDP(sport=5000, dport=5001)
    packets.append(multicast)
    
    print(f"[OK] Generated {len(packets)} test packets")
    return packets

def main():
    """Generate the test PCAP file."""
    print("Generating Wireless (802.11) Test PCAP...")
    print("=" * 50)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate packets
    packets = create_wireless_test_packets()
    
    # Write to PCAP file
    output_file = os.path.join(output_dir, "wireless_test.pcap")
    wrpcap(output_file, packets)
    
    print("=" * 50)
    print(f"[OK] Test PCAP saved to: {output_file}")
    print(f"[OK] Total packets: {len(packets)}")
    print(f"[OK] File size: {os.path.getsize(output_file)} bytes")
    print("\nThis PCAP can be used to test PyShark Wireless display filters!")

if __name__ == "__main__":
    main()