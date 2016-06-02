pyshark
=======

Python wrapper for tshark, allowing python packet parsing using wireshark dissectors.

There are quite a few python packet parsing modules, this one is different because it doesn't actually parse any packets, it simply uses tshark's (wireshark command-line utility) ability to export XMLs to use its parsing.

This package allows parsing from a capture file or a live capture, using all wireshark dissectors you have installed.
Tested on windows/linux.

Usage
=====

Reading from a capture file:
----------------------------

::

    import pyshark
    cap = pyshark.FileCapture('/tmp/mycapture.cap')
    cap
    >>> <FileCapture /tmp/mycapture.cap (589 packets)>
    print cap[0]
    Packet (Length: 698)
    Layer ETH:
            Destination: BLANKED
            Source: BLANKED
            Type: IP (0x0800)
    Layer IP:
            Version: 4
            Header Length: 20 bytes
            Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport))
            Total Length: 684s
            Identification: 0x254f (9551)
            Flags: 0x00
            Fragment offset: 0
            Time to live: 1
            Protocol: UDP (17)
            Header checksum: 0xe148 [correct]
            Source: BLANKED
            Destination: BLANKED
      ...

  
Reading from a live interface:
------------------------------

::

    capture = pyshark.LiveCapture(interface='eth0')
    capture.sniff(timeout=50)
    capture
    >>> <LiveCapture (5 packets)>
    capture[3]
    <UDP/HTTP Packet>

    for packet in capture.sniff_continuously(packet_count=5):
        print 'Just arrived:', packet

Infinite reading from a live interface with capture filter:
------------------------------

::

    def packet_captured(packet):
      print 'Just arrived:', packet

    capture = pyshark.LiveCapture(interface='eth0', capture_filter='tcp')
    capture.apply_on_packets(packet_captured)

Accessing packet data:
----------------------

Data can be accessed in multiple ways. 
Packets are divided into layers, first you have to reach the appropriate layer and then you can select your field.

All of the following work::

    packet['ip'].dst
    >>> 192.168.0.1
    packet.ip.src
    >>> 192.168.0.100
    packet[2].src
    >>> 192.168.0.100

