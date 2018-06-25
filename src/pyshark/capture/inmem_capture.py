import os
import struct
import time
import warnings

import trollius as asyncio
from trollius import subprocess, From, Return

from pyshark.capture.capture import Capture, StopCapture

DEFAULT_TIMEOUT = 30


class LinkTypes(object):
    NULL = 0
    ETHERNET = 1
    IEEE802_5 = 6
    PPP = 9
    IEEE802_11 = 105


class InMemCapture(Capture):

    def __init__(self, bpf_filter=None, display_filter=None, only_summaries=False,
                  decryption_key=None, encryption_type='wpa-pwk', decode_as=None,
                  disable_protocol=None, tshark_path=None, override_prefs=None, use_json=False,
                  linktype=LinkTypes.ETHERNET, include_raw=False):
        """
        Creates a new in-mem capture, a capture capable of receiving binary packets and parsing them using tshark.
        Significantly faster if packets are added in a batch.

        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD',
        or 'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.

        """
        super(InMemCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                           decryption_key=decryption_key, encryption_type=encryption_type,
                                           decode_as=decode_as, disable_protocol=disable_protocol,
                                           tshark_path=tshark_path, override_prefs=override_prefs,
                                           use_json=use_json, include_raw=include_raw)
        self.bpf_filter = bpf_filter
        self._packets_to_write = None
        self._current_linktype = linktype
        self._current_tshark = None

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(InMemCapture, self).get_parameters(packet_count=packet_count)
        params += ['-i', '-']
        return params

    @asyncio.coroutine
    def _get_tshark_process(self, packet_count=None):
        if self._current_tshark:
            raise Return(self._current_tshark)
        proc = yield From(super(InMemCapture, self)._get_tshark_process(packet_count=packet_count, stdin=subprocess.PIPE))
        self._current_tshark = proc

        # Create PCAP header
        header = struct.pack("IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 0x7fff, self._current_linktype)
        proc.stdin.write(header)
        raise Return(proc)

    @classmethod
    def _get_json_separator(cls):
        return ("}%s%s" % (os.linesep, os.linesep)).encode()

    def _write_packet(self, packet):
        # Write packet header
        self._current_tshark.stdin.write(struct.pack("IIII", int(time.time()), 0, len(packet), len(packet)))
        self._current_tshark.stdin.write(packet)

    def parse_packet(self, binary_packet):
        """
        Parses a single binary packet and returns its parsed version.

        DOES NOT CLOSE tshark. It must be closed manually by calling close() when you're done
        working with it.
        Use parse_packets when parsing multiple packets for faster parsing
        """
        return self.parse_packets([binary_packet])[0]

    def parse_packets(self, binary_packets):
        """
        Parses binary packets and return a list of parsed packets.

        DOES NOT CLOSE tshark. It must be closed manually by calling close() when you're done
        working with it.
        """
        if not binary_packets:
            raise ValueError("Must supply at least one packet")
        parsed_packets = []

        if not self._current_tshark:
            self.eventloop.run_until_complete(self._get_tshark_process())
        for binary_packet in binary_packets:
            self._write_packet(binary_packet)

        def callback(pkt):
            parsed_packets.append(pkt)
            if len(parsed_packets) == len(binary_packets):
                raise StopCapture()

        self.eventloop.run_until_complete(self._get_parsed_packet_from_tshark(callback))
        return parsed_packets

    @asyncio.coroutine
    def _get_parsed_packet_from_tshark(self, callback):
        yield From(self._current_tshark.stdin.drain())
        try:
            yield From(asyncio.wait_for(self.packets_from_tshark(callback, close_tshark=False),
                                       DEFAULT_TIMEOUT))
        except asyncio.TimeoutError:
            self.close()
            raise asyncio.TimeoutError("Timed out while waiting for tshark to parse packet. "
                                       "Try rerunning with cap.set_debug() to see tshark errors. "
                                       "Closing tshark..")

    def close(self):
        self._current_tshark = None
        super(InMemCapture, self).close()

    def feed_packet(self, binary_packet, linktype=LinkTypes.ETHERNET):
        """
        DEPRECATED. Use parse_packet instead.
        This function adds the packet to the packets list, and also closes and reopens tshark for
        each packet.
        ==============

        Gets a binary (string) packet and parses & adds it to this capture.
        Returns the added packet.

        Use feed_packets if you have multiple packets to insert.

        By default, assumes the packet is an ethernet packet. For another link type, supply the linktype argument (most
        can be found in the class LinkTypes)
        """
        warnings.warn("Deprecated method. Use InMemCapture.parse_packet() instead.")
        self._current_linktype = linktype
        pkt = self.parse_packet(binary_packet)
        self.close()
        self._packets.append(pkt)
        return pkt

    def feed_packets(self, binary_packets, linktype=LinkTypes.ETHERNET):
        """
        Gets a list of binary packets, parses them using tshark and returns their parsed values.
        Keeps the packets in the internal packet list as well.

        By default, assumes the packets are ethernet packets. For another link type, supply the linktype argument (most
        can be found in the class LinkTypes)
        """
        self._current_linktype = linktype
        parsed_packets = self.parse_packets(binary_packets)
        self._packets.extend(parsed_packets)
        self.close()
        return parsed_packets
