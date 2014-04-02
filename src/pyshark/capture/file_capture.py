from pyshark.capture.capture import Capture


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, lazy=True, keep_packets=True, display_filter=None):
        """
        Creates a packet capture object by reading from file.

        :param lazy: Whether to lazily get packets from the cap file or read all of them immediately.
        :param keep_packets: Whether to keep packets after reading them via next(). Used to conserve memory when reading
        large caps (can only be used along with the "lazy" option!)
        :param input_file: Either a path or a file-like object containing either a packet capture file (PCAP, PCAP-NG..)
        or a TShark xml.
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        """
        super(FileCapture, self).__init__(display_filter=display_filter)
        if isinstance(input_file, basestring):
            self.input_file = open(input_file, 'rb')
        else:
            self.input_file = input_file

        self.lazy = lazy
        self.keep_packets = keep_packets
        if not lazy:
            self._packets = list(self.packets_from_file(self.input_file))
            self._packet_generator = None
        else:
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
        if self.lazy:
            # We may not yet have this packet
            packet = None
            while packet_index >= len(self._packets):
                try:
                    self.next()
                except StopIteration:
                    # We read the whole file, and there's still not such packet.
                    raise KeyError('Packet of index %d does not exist in capture' % packet_index)
            return super(FileCapture, self).__getitem__(packet_index)
        else:
            return super(FileCapture, self).__getitem__(packet_index)


    def packets_from_file(self, cap_or_xml):
        """
        Gets an xml file data and returns the packets.
        """
        beginning = cap_or_xml.read(20)
        if b'<?xml' in beginning:
            # It's an xml file.
            return self._packets_from_fd(cap_or_xml, previous_data=beginning, wait_for_more_data=False)
        else:
            # We assume it's a PCAP file and use tshark to get the XML.
            p = self._get_tshark_process(extra_params=['-r', cap_or_xml.name])
            return self._packets_from_fd(p.stdout, previous_data=beginning, wait_for_more_data=False)

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