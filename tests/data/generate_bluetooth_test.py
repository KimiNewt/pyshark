#!/usr/bin/env python3
"""
Generate Bluetooth Test PCAP for PyShark Display Filter Testing
================================================================

This script creates a test pcap file with various Bluetooth frames
to validate the bluetooth display filters in PyShark.

Dependencies: scapy
Usage: python generate_bluetooth_test.py
Output: bluetooth_test.pcap
"""

from scapy.all import *
from scapy.layers.bluetooth import *
try:
    from scapy.layers.bluetooth4LE import *
except ImportError:
    # Fallback for older scapy versions
    pass
import os

def create_bluetooth_test_packets():
    """Create a variety of Bluetooth test packets."""
    packets = []
    
    # Basic HCI packets
    print("[OK] Creating HCI packets...")
    
    # 1. HCI Command packet
    hci_cmd = HCI_Hdr(type=1) / HCI_Command_Hdr(opcode=0x1001, len=3) / Raw(b"\x01\x02\x03")
    packets.append(hci_cmd)
    
    # 2. HCI Event packet
    hci_event = HCI_Hdr(type=4) / HCI_Event_Hdr(code=0x0e, len=4) / Raw(b"\x01\x01\x10\x00")
    packets.append(hci_event)
    
    # 3. HCI ACL Data packet
    hci_acl = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0001, PB=2, BC=0, len=8) / Raw(b"\x04\x00\x01\x02\x03\x04\x05\x06")
    packets.append(hci_acl)
    
    # L2CAP packets
    print("[OK] Creating L2CAP packets...")
    
    # 4. L2CAP signaling packet
    l2cap_sig = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0001, PB=2, BC=0, len=12) / \
                L2CAP_Hdr(cid=1, len=8) / L2CAP_CmdHdr(code=8, id=1, len=4) / \
                L2CAP_InfoReq(type=2)
    packets.append(l2cap_sig)
    
    # 5. L2CAP data packet
    l2cap_data = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0002, PB=2, BC=0, len=16) / \
                 L2CAP_Hdr(cid=0x0040, len=12) / Raw(b"Hello Bluetooth")
    packets.append(l2cap_data)
    
    # 6. L2CAP Connection Request
    l2cap_conn_req = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0003, PB=2, BC=0, len=16) / \
                     L2CAP_Hdr(cid=1, len=12) / L2CAP_CmdHdr(code=2, id=2, len=8) / \
                     L2CAP_ConnReq(psm=0x1001, scid=0x0041)
    packets.append(l2cap_conn_req)
    
    # 7. L2CAP Connection Response
    l2cap_conn_resp = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0003, PB=2, BC=0, len=20) / \
                      L2CAP_Hdr(cid=1, len=16) / L2CAP_CmdHdr(code=3, id=2, len=12) / \
                      L2CAP_ConnResp(dcid=0x0042, scid=0x0041, result=0, status=0)
    packets.append(l2cap_conn_resp)
    
    # SDP packets
    print("[OK] Creating SDP packets...")
    
    # 8. SDP Service Search Request
    sdp_search = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0004, PB=2, BC=0, len=20) / \
                 L2CAP_Hdr(cid=0x0041, len=16) / Raw(b"\x02\x00\x01\x00\x08\x35\x03\x19\x11\x00\x00\x01\x00\x00")
    packets.append(sdp_search)
    
    # RFCOMM packets
    print("[OK] Creating RFCOMM packets...")
    
    # 9. RFCOMM SABM (Set Asynchronous Balanced Mode)
    rfcomm_sabm = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0005, PB=2, BC=0, len=12) / \
                  L2CAP_Hdr(cid=0x0043, len=8) / Raw(b"\x03\x3f\x01\x1c\xd7\xea")
    packets.append(rfcomm_sabm)
    
    # 10. RFCOMM UA (Unnumbered Acknowledgement)
    rfcomm_ua = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0005, PB=2, BC=0, len=12) / \
                L2CAP_Hdr(cid=0x0043, len=8) / Raw(b"\x03\x73\x01\x00\x50\xa5")
    packets.append(rfcomm_ua)
    
    # 11. RFCOMM UIH (Unnumbered Information with Header check)
    rfcomm_uih = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0005, PB=2, BC=0, len=16) / \
                 L2CAP_Hdr(cid=0x0043, len=12) / Raw(b"\x03\xef\x09\x41\x54\x2b\x43\x47\x4d\x49\x0d\x70")
    packets.append(rfcomm_uih)
    
    # A2DP/AVDTP packets
    print("[OK] Creating A2DP/AVDTP packets...")
    
    # 12. AVDTP Discover Command
    avdtp_discover = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0006, PB=2, BC=0, len=12) / \
                     L2CAP_Hdr(cid=0x0044, len=8) / Raw(b"\x00\x01\x01\x00")
    packets.append(avdtp_discover)
    
    # HID packets
    print("[OK] Creating HID packets...")
    
    # 13. HID Control packet
    hid_control = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0007, PB=2, BC=0, len=12) / \
                  L2CAP_Hdr(cid=0x0011, len=8) / Raw(b"\x00\x00\x00\x00")
    packets.append(hid_control)
    
    # 14. HID Interrupt packet (mouse movement)
    hid_interrupt = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0007, PB=2, BC=0, len=12) / \
                    L2CAP_Hdr(cid=0x0013, len=8) / Raw(b"\xa1\x01\x00\x02\xff\x00")
    packets.append(hid_interrupt)
    
    # ATT/GATT packets (Bluetooth LE)
    print("[OK] Creating ATT/GATT packets...")
    
    # 15. ATT Read Request
    att_read_req = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0008, PB=2, BC=0, len=12) / \
                   L2CAP_Hdr(cid=0x0004, len=8) / Raw(b"\x0a\x03\x00")
    packets.append(att_read_req)
    
    # 16. ATT Read Response
    att_read_resp = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0008, PB=2, BC=0, len=16) / \
                    L2CAP_Hdr(cid=0x0004, len=12) / Raw(b"\x0b\x48\x65\x6c\x6c\x6f\x20\x47\x41\x54\x54")
    packets.append(att_read_resp)
    
    # 17. ATT Write Request
    att_write_req = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0008, PB=2, BC=0, len=20) / \
                    L2CAP_Hdr(cid=0x0004, len=16) / Raw(b"\x12\x05\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    packets.append(att_write_req)
    
    # 18. ATT Write Response
    att_write_resp = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0008, PB=2, BC=0, len=8) / \
                     L2CAP_Hdr(cid=0x0004, len=4) / Raw(b"\x13")
    packets.append(att_write_resp)
    
    # Security Manager Protocol (SMP) packets
    print("[OK] Creating SMP packets...")
    
    # 19. SMP Pairing Request
    smp_pair_req = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0009, PB=2, BC=0, len=16) / \
                   L2CAP_Hdr(cid=0x0006, len=12) / Raw(b"\x01\x04\x00\x01\x10\x07\x07\x00\x00")
    packets.append(smp_pair_req)
    
    # 20. SMP Pairing Response
    smp_pair_resp = HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=0x0009, PB=2, BC=0, len=16) / \
                    L2CAP_Hdr(cid=0x0006, len=12) / Raw(b"\x02\x00\x00\x01\x10\x07\x07\x00\x00")
    packets.append(smp_pair_resp)
    
    # Different HCI event types
    print("[OK] Creating various HCI events...")
    
    # 21. Connection Complete Event
    conn_complete = HCI_Hdr(type=4) / HCI_Event_Hdr(code=0x03, len=11) / \
                    Raw(b"\x00\x01\x00\x12\x34\x56\x78\x9a\xbc\x01\x00")
    packets.append(conn_complete)
    
    # 22. Disconnection Complete Event
    disconn_complete = HCI_Hdr(type=4) / HCI_Event_Hdr(code=0x05, len=4) / \
                       Raw(b"\x00\x01\x00\x13")
    packets.append(disconn_complete)
    
    # 23. Inquiry Result Event
    inquiry_result = HCI_Hdr(type=4) / HCI_Event_Hdr(code=0x02, len=15) / \
                     Raw(b"\x01\x12\x34\x56\x78\x9a\xbc\x01\x02\x03\x00\x00\x00\x00\x00")
    packets.append(inquiry_result)
    
    # 24. Number of Completed Packets Event
    num_complete = HCI_Hdr(type=4) / HCI_Event_Hdr(code=0x13, len=5) / \
                   Raw(b"\x01\x01\x00\x01\x00")
    packets.append(num_complete)
    
    # Different HCI command types
    print("[OK] Creating various HCI commands...")
    
    # 25. Inquiry Command
    inquiry_cmd = HCI_Hdr(type=1) / HCI_Command_Hdr(opcode=0x0401, len=5) / \
                  Raw(b"\x33\x8b\x9e\x05\x00")
    packets.append(inquiry_cmd)
    
    # 26. Create Connection Command
    create_conn = HCI_Hdr(type=1) / HCI_Command_Hdr(opcode=0x0405, len=13) / \
                  Raw(b"\x12\x34\x56\x78\x9a\xbc\x18\xcc\x01\x00\x00\x00\x01")
    packets.append(create_conn)
    
    # 27. Accept Connection Request Command
    accept_conn = HCI_Hdr(type=1) / HCI_Command_Hdr(opcode=0x0409, len=7) / \
                  Raw(b"\x12\x34\x56\x78\x9a\xbc\x00")
    packets.append(accept_conn)
    
    # 28. Read Remote Name Request
    read_name = HCI_Hdr(type=1) / HCI_Command_Hdr(opcode=0x0419, len=10) / \
                Raw(b"\x12\x34\x56\x78\x9a\xbc\x01\x00\x00\x00")
    packets.append(read_name)
    
    print(f"[OK] Generated {len(packets)} test packets")
    return packets

def main():
    """Generate the test PCAP file."""
    print("Generating Bluetooth Test PCAP...")
    print("=" * 50)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate packets
    packets = create_bluetooth_test_packets()
    
    # Write to PCAP file
    output_file = os.path.join(output_dir, "bluetooth_test.pcap")
    wrpcap(output_file, packets)
    
    print("=" * 50)
    print(f"[OK] Test PCAP saved to: {output_file}")
    print(f"[OK] Total packets: {len(packets)}")
    print(f"[OK] File size: {os.path.getsize(output_file)} bytes")
    print("\nThis PCAP can be used to test PyShark Bluetooth display filters!")

if __name__ == "__main__":
    main()