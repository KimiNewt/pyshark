import subprocess
from pyshark.capture.capture import Capture
from pyshark.tshark.tshark import get_tshark_path


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None, lazy=False, discard=False):
        """
        Creates a packet capture object by reading from file.

        :param lazy: Whether to lazily get packets from the cap file or read all of them immediately.
        :param discard: Whether to discard packets from memory after interpreting them
        :param input_file: Either a path or a file-like object containing either a packet capture file (PCAP, PCAP-NG..)
        or a TShark xml.
        """
        super(FileCapture, self).__init__()
        if isinstance(input_file, basestring):
            self.input_file = file(input_file, 'rb')
        else:
            self.input_file = input_file

        self.discard = discard

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
        if self._packet_generator:
            packet = self._packet_generator.next()
            if not self.discard:
                self._packets += [packet]
            return packet
        else:
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
            p = subprocess.Popen([get_tshark_path(),
                      '-T', 'pdml',
                      '-r', cap_or_xml.name],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            return self._packets_from_fd(p.stdout, previous_data=beginning, wait_for_more_data=False)

    def __repr__(self):
        return '<%s %s (%d packets)>' %(self.__class__.__name__, self.filename, len(self._packets))

    @property
    def filename(self):
        """
        Returns the filename of the capture file represented by this object.
        """
        return self.input_file.name