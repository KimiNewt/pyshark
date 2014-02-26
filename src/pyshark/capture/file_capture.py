from pyshark.capture.capture import Capture


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, lazy=True, display_filter=None):
        """
        Creates a packet capture object by reading from file.

        :param lazy: Whether to lazily get packets from the cap file or read all of them immediately.
        :param input_file: Either a path or a file-like object containing either a packet capture file (PCAP, PCAP-NG..)
        or a TShark xml.
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        :param display_filter: A display (wireshark) filter to apply on the cap before reading it.
        """
        super(FileCapture, self).__init__(display_filter=display_filter)
        if isinstance(input_file, basestring):
            self.input_file = file(input_file, 'rb')
        else:
            self.input_file = input_file

        self.lazy = lazy
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
        if self._packet_generator and self.current_packet >= len(self._packets):
            packet = self._packet_generator.next()
            if not self.lazy:
                self._packets += [packet]
            else:
                # If we're in lazy mode we'd like to conserve memory and not save all seen packets,
                # but simply iterate one-by-one
                return packet
        return super(FileCapture, self).next()

    def __getitem__(self, packet_index):
        if self._packet_generator:
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
        Gets an xml file data and returns the raw xml and a list of packets.

        :return tuple of (raw_xml_file, packets)
        """
        beginning = cap_or_xml.read(5)
        if beginning == '<?xml':
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