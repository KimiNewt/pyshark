import os
import sys
from pyshark.capture.capture import Capture

# Define basestring as str if we're in python3.
if sys.version_info >= (3, 0):
    basestring = str


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, keep_packets=True, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type='wpa-pwk', decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None,
                 use_json=False, output_file=None, include_raw=False, eventloop=None, custom_parameters=None):
        """
        Creates a packet capture object by reading from file.

        :param keep_packets: Whether to keep packets after reading them via next(). Used to conserve memory when reading
        large caps (can only be used along with the "lazy" option!)
        :param input_file: File path of the capture (PCAP, PCAPNG)
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information.
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param disable_protocol: Tells tshark to remove a dissector for a specific protocol.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). It is a good deal faster than XML
        but also has less information. Available from Wireshark 2.2.0.
        :param output_file: A string of a file to write every read packet into (useful when filtering).
        :param custom_parameters: A dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        """
        super(FileCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries,
                                          decryption_key=decryption_key, encryption_type=encryption_type,
                                          decode_as=decode_as, disable_protocol=disable_protocol, tshark_path=tshark_path,
                                          override_prefs=override_prefs, use_json=use_json, output_file=output_file,
                                          include_raw=include_raw, eventloop=eventloop, custom_parameters=custom_parameters)
        self.input_filename = input_file
        if not isinstance(input_file, basestring):
            self.input_filename = input_file.name
        if not os.path.exists(self.input_filename):
            raise FileNotFoundError(str(self.input_filename))
        self.keep_packets = keep_packets
        self._packet_generator = self._packets_from_tshark_sync()

    def next(self):
        """
        Returns the next packet in the cap.
        If the capture's keep_packets flag is True, will also keep it in the internal packet list.
        """
        if not self.keep_packets:
            return self._packet_generator.send(None)
        elif self._current_packet >= len(self._packets):
            packet = self._packet_generator.send(None)
            self._packets += [packet]
        return super(FileCapture, self).next_packet()

    def __getitem__(self, packet_index):
        if not self.keep_packets:
            raise NotImplementedError("Cannot use getitem if packets are not kept")
            # We may not yet have this packet
        while packet_index >= len(self._packets):
            try:
                self.next()
            except StopIteration:
                # We read the whole file, and there's still not such packet.
                raise KeyError('Packet of index %d does not exist in capture' % packet_index)
        return super(FileCapture, self).__getitem__(packet_index)

    def get_parameters(self, packet_count=None):
        return super(FileCapture, self).get_parameters(packet_count=packet_count) + ['-r', self.input_filename]

    def __repr__(self):
        if self.keep_packets:
            return '<%s %s>' % (self.__class__.__name__, self.input_filename)
        else:
            return '<%s %s (%d packets)>' % (self.__class__.__name__, self.input_filename, len(self._packets))
