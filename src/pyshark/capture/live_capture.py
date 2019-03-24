import os

import asyncio

from pyshark.capture.capture import Capture
from pyshark.tshark.tshark import get_tshark_interfaces, get_process_path
import sys

# Define basestring as str if we're in python3.
if sys.version_info >= (3, 0):
    basestring = str


class LiveCapture(Capture):
    """
    Represents a live capture on a network interface.
    """

    def __init__(self, interface=None, bpf_filter=None, display_filter=None, only_summaries=False, decryption_key=None,
                 encryption_type='wpa-pwk', output_file=None, decode_as=None, disable_protocol=None, tshark_path=None,
                 override_prefs=None, capture_filter=None, monitor_mode=None, use_json=False, include_raw=False,
                 eventloop=None, custom_parameters=None):
        """
        Creates a new live capturer on a given interface. Does not start the actual capture itself.

        :param interface: Name of the interface to sniff on or a list of names (str). If not given, runs on all interfaces.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        :param output_file: Additionally save live captured packets to this file.
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param capture_filter: Capture (wireshark) filter to use.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). It is a good deal faster than XML
        but also has less information. Available from Wireshark 2.2.0.
        :param custom_parameters: A dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        """
        super(LiveCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                          decryption_key=decryption_key, encryption_type=encryption_type,
                                          output_file=output_file, decode_as=decode_as, disable_protocol=disable_protocol,
                                          tshark_path=tshark_path, override_prefs=override_prefs,
                                          capture_filter=capture_filter, use_json=use_json, include_raw=include_raw,
                                          eventloop=eventloop, custom_parameters=custom_parameters)
        self.bpf_filter = bpf_filter
        self.monitor_mode = monitor_mode

        if sys.platform == 'win32' and monitor_mode:
            raise WindowsError('Monitor mode is not supported by the Windows platform')

        if interface is None:
            self.interfaces = get_tshark_interfaces(tshark_path)
        elif isinstance(interface, basestring):
            self.interfaces = [interface]
        else:
            self.interfaces = interface

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(LiveCapture, self).get_parameters(packet_count=packet_count)
        # Read from STDIN
        params += ['-r', '-']
        return params

    def _get_dumpcap_parameters(self):
        # Don't report packet counts, use pcap format
        params = ["-q", "-P"]
        if self.bpf_filter:
            params += ['-f', self.bpf_filter]
        if self.monitor_mode:
            params += ['-I']
        for interface in self.interfaces:
            params += ['-i', interface]
        # Write to STDOUT
        params += ["-w", "-"]
        return params

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        read, write = os.pipe()

        dumpcap_params = [get_process_path(process_name="dumpcap", tshark_path=self.tshark_path)] + self._get_dumpcap_parameters()

        self._log.debug("Creating Dumpcap subprocess with parameters: %s" % " ".join(dumpcap_params))
        dumpcap_process = await asyncio.create_subprocess_exec(*dumpcap_params, stdout=write,
                                                               stderr=self._stderr_output())
        self._created_new_process(dumpcap_params, dumpcap_process, process_name="Dumpcap")

        tshark = await super(LiveCapture, self)._get_tshark_process(packet_count=packet_count, stdin=read)
        return tshark

    # Backwards compatibility
    sniff = Capture.load_packets

    def sniff_continuously(self, packet_count=None):
        """
        Captures from the set interface, returning a generator which returns packets continuously.

        Can be used as follows:
        for packet in capture.sniff_continuously();
            print 'Woo, another packet:', packet

        Note: you can also call capture.apply_on_packets(packet_callback) which should have a slight performance boost.

        :param packet_count: an amount of packets to capture, then stop.
        """
        # Retained for backwards compatibility and to add documentation.
        return self._packets_from_tshark_sync(packet_count=packet_count)
