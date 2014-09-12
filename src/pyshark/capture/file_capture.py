from pyshark.capture.capture import Capture


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, keep_packets=True, display_filter=None, only_summaries=False):
        """
        Creates a packet capture object by reading from file.

        :param keep_packets: Whether to keep packets after reading them via next(). Used to conserve memory when reading
        large caps (can only be used along with the "lazy" option!)
        :param input_file: File path of the capture (PCAP, PCAPNG)
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        """
        super(FileCapture, self).__init__(display_filter=display_filter, only_summaries=only_summaries)
        self.input_file = input_file
        if not isinstance(input_file, basestring):
            self.input_file = input_file.name

        self.keep_packets = keep_packets
        self._packets = []
        self._packet_generator = self.packets_from_file(self.input_file)

    def close(self):
        if not self.input_file.closed:
            self.input_file.close()

    def next(self):
        if self.lazy:
            if not self.keep_packets:
                return self._packet_generator.next()
            elif self.current_packet >= len(self._packets):
                packet = self._packet_generator.next()
                self._packets += [packet]
        return super(FileCapture, self).next_packet()

    def __getitem__(self, packet_index):
        if not self.keep_packets:
            raise NotImplementedError("Cannot use getitem if packets are not kept")
        # We may not yet have this packet
        packet = None
        while packet_index >= len(self._packets):
            try:
                self.next()
            except StopIteration:
                # We read the whole file, and there's still not such packet.
                raise KeyError('Packet of index %d does not exist in capture' % packet_index)
        return super(FileCapture, self).__getitem__(packet_index)

    def packets_from_file(self, cap_or_xml):
        """
        Gets an xml file data and returns the packets.
        """
        beginning = cap_or_xml.read(20)
        if b'<?xml' in beginning:
            # It's an xml file.
            for packet in self._get_packets_from_fd(cap_or_xml, previous_data=beginning):
                yield packet
        else:
            # We assume it's a PCAP file and use tshark to get the XML.
            self._set_tshark_process_sync()
            for packet in self._get_packets_from_fd(self.tshark_process.stdout):
                yield packet

    def get_parameters(self, packet_count=None):
        return super(FileCapture, self).get_parameters(packet_count=packet_count) + ['-r', self.input_file]

    def __repr__(self):
        if self.lazy:
            return '<%s %s>' %(self.__class__.__name__, self.filename)
        else:
            return '<%s %s (%d packets)>' %(self.__class__.__name__, self.filename, len(self._packets))

    @property
    def filename(self):
        """
        Returns the filename of the capture file represented by this object.
        """
        return self.input_file.name