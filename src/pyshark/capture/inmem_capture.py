import struct
import time

import trollius as asyncio
from trollius import subprocess, From, Return

from pyshark.capture.capture import Capture


class LinkTypes(object):
    NULL = 0
    ETHERNET = 1
    IEEE802_5 = 6
    PPP = 9
    IEEE802_11 = 105


class InMemCapture(Capture):

    def __init__(self, bpf_filter=None, display_filter=None, only_summaries=False,
                  decryption_key=None, encryption_type='wpa-pwk'):
        """
        Creates a new in-mem capture, a capture capable of receiving binary packets and parsing them using tshark.
        Currently opens a new instance of tshark for every packet buffer,
        so it is very slow -- try inserting more than one packet at a time if possible.

        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD',
        or 'WPA-PWK'. Defaults to WPA-PWK).
        """
        super(InMemCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                           decryption_key=decryption_key, encryption_type=encryption_type)
        self.bpf_filter = bpf_filter
        self._packets_to_write = None
        self._current_linktype = None

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(InMemCapture, self).get_parameters(packet_count=packet_count)
        params += ['-i', '-']
        return params

    @asyncio.coroutine
    def _get_tshark_process(self, packet_count=None):
        proc = yield From(super(InMemCapture, self)._get_tshark_process(packet_count=packet_count, stdin=subprocess.PIPE))
        self._tshark_stdin = proc.stdin

        # Create PCAP header
        header = struct.pack("IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 0x7fff, self._current_linktype)
        proc.stdin.write(header)

        for packet in self._packets_to_write:
            # Write packet header
            proc.stdin.write(struct.pack("IIII", int(time.time()), 0, len(packet), len(packet)))
            proc.stdin.write(packet)
        proc.stdin.close()
        raise Return(proc)

    def feed_packet(self, binary_packet, linktype=LinkTypes.ETHERNET):
        """
        Gets a binary (string) packet and parses & adds it to this capture.
        Returns the added packet.

        Use feed_packets if you have multiple packets to insert.

        By default, assumes the packet is an ethernet packet. For another link type, supply the linktype argument (most
        can be found in the class LinkTypes)
        """
        return self.feed_packets([binary_packet], linktype=linktype)[0]

    def feed_packets(self, binary_packets, linktype=LinkTypes.ETHERNET):
        """
        Gets a list of binary packets, parses them using tshark and returns their parsed values.
        Keeps the packets in the internal packet list as well.

        By default, assumes the packets are ethernet packets. For another link type, supply the linktype argument (most
        can be found in the class LinkTypes)
        """
        self._packets_to_write = binary_packets
        self._current_linktype = linktype
        self.load_packets(packet_count=len(binary_packets))
        return self[-len(binary_packets):]
