import asyncio
import datetime
import itertools
import subprocess
import os
import struct
import time
import warnings
from packaging import version

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
                 disable_protocol=None, tshark_path=None, override_prefs=None, use_json=False, use_ek=False,
                 linktype=LinkTypes.ETHERNET, include_raw=False, eventloop=None, custom_parameters=None,
                 debug=False):
        """Creates a new in-mem capture, a capture capable of receiving binary packets and parsing them using tshark.

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
        :param custom_parameters: A dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        or else a list of parameters in the format ["--foo", "bar", "--baz", "foo"].
        """
        super(InMemCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                           decryption_key=decryption_key, encryption_type=encryption_type,
                                           decode_as=decode_as, disable_protocol=disable_protocol,
                                           tshark_path=tshark_path, override_prefs=override_prefs,
                                           use_json=use_json, use_ek=use_ek,
                                           include_raw=include_raw, eventloop=eventloop,
                                           custom_parameters=custom_parameters, debug=debug)
        self.bpf_filter = bpf_filter
        self._packets_to_write = None
        self._current_linktype = linktype
        self._current_tshark = None

    def get_parameters(self, packet_count=None):
        """Returns the special tshark parameters to be used according to the configuration of this class."""
        params = super(InMemCapture, self).get_parameters(
            packet_count=packet_count)
        params += ['-i', '-']
        return params

    async def _get_tshark_process(self, packet_count=None):
        if self._current_tshark:
            return self._current_tshark
        proc = await super(InMemCapture, self)._get_tshark_process(packet_count=packet_count, stdin=subprocess.PIPE)
        self._current_tshark = proc

        # Create PCAP header
        header = struct.pack("IHHIIII", 0xa1b2c3d4, 2, 4,
                             0, 0, 0x7fff, self._current_linktype)
        proc.stdin.write(header)

        return proc

    def _get_json_separators(self):
        """"Returns the separators between packets in a JSON output

        Returns a tuple of (packet_separator, end_of_file_separator, characters_to_disregard).
        The latter variable being the number of characters to ignore in order to pass the packet (i.e. extra newlines,
        commas, parenthesis).
        """
        if self._get_tshark_version() >= version.parse("2.6.7"):
            return f"{os.linesep}  }}".encode(), f"}}{os.linesep}]".encode(), 0
        else:
            return f'}}{os.linesep}{os.linesep}'.encode(), f"}}{os.linesep}{os.linesep}]", 1

    def _write_packet(self, packet, sniff_time):
        if sniff_time is None:
            now = time.time()
        elif isinstance(sniff_time, datetime.datetime):
            now = sniff_time.timestamp()
        else:
            now = float(sniff_time)
        secs = int(now)
        usecs = int((now * 1000000) % 1000000)
        # Write packet header
        self._current_tshark.stdin.write(struct.pack(
            "IIII", secs, usecs, len(packet), len(packet)))
        self._current_tshark.stdin.write(packet)

    def parse_packet(self, binary_packet, sniff_time=None, timeout=DEFAULT_TIMEOUT):
        """Parses a single binary packet and returns its parsed version.

        DOES NOT CLOSE tshark. It must be closed manually by calling close() when you're done
        working with it.
        Use parse_packets when parsing multiple packets for faster parsing
        """
        if sniff_time is not None:
            sniff_time = [sniff_time]
        return self.parse_packets([binary_packet], sniff_time, timeout)[0]

    def parse_packets(self, binary_packets, sniff_times=None, timeout=DEFAULT_TIMEOUT):
        """Parses binary packets and return a list of parsed packets.

        DOES NOT CLOSE tshark. It must be closed manually by calling close() when you're done
        working with it.
        """
        if self.eventloop is None:
            self._setup_eventloop()
        return self.eventloop.run_until_complete(self.parse_packets_async(binary_packets, sniff_times, timeout))

    async def parse_packets_async(self, binary_packets, sniff_times=None, timeout=DEFAULT_TIMEOUT):
        """A coroutine which parses binary packets and return a list of parsed packets.

        DOES NOT CLOSE tshark. It must be closed manually by calling close() when you're done
        working with it.
        """
        parsed_packets = []
        if sniff_times is None:
            sniff_times = []
        if not self._current_tshark:
            await self._get_tshark_process()
        for binary_packet, sniff_time in itertools.zip_longest(binary_packets, sniff_times):
            self._write_packet(binary_packet, sniff_time)

        def callback(pkt):
            parsed_packets.append(pkt)
            if len(parsed_packets) == len(binary_packets):
                raise StopCapture()

        await self._get_parsed_packet_from_tshark(callback, timeout)
        return parsed_packets

    async def _get_parsed_packet_from_tshark(self, callback, timeout):
        await self._current_tshark.stdin.drain()
        try:
            await asyncio.wait_for(self.packets_from_tshark(callback, close_tshark=False), timeout)
        except asyncio.TimeoutError:
            await self.close_async()
            raise asyncio.TimeoutError("Timed out while waiting for tshark to parse packet. "
                                       "Try rerunning with cap.set_debug() to see tshark errors. "
                                       "Closing tshark..")

    async def close_async(self):
        self._current_tshark = None
        await super(InMemCapture, self).close_async()

    def feed_packet(self, binary_packet, linktype=LinkTypes.ETHERNET, timeout=DEFAULT_TIMEOUT):
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
        warnings.warn(
            "Deprecated method. Use InMemCapture.parse_packet() instead.")
        self._current_linktype = linktype
        pkt = self.parse_packet(binary_packet, timeout=timeout)
        self.close()
        self._packets.append(pkt)
        return pkt

    def feed_packets(self, binary_packets, linktype=LinkTypes.ETHERNET, timeout=DEFAULT_TIMEOUT):
        """Gets a list of binary packets, parses them using tshark and returns their parsed values.

        Keeps the packets in the internal packet list as well.

        By default, assumes the packets are ethernet packets. For another link type, supply the linktype argument (most
        can be found in the class LinkTypes)
        """
        self._current_linktype = linktype
        parsed_packets = self.parse_packets(binary_packets, timeout=timeout)
        self._packets.extend(parsed_packets)
        self.close()
        return parsed_packets
