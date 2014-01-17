import subprocess
from pyshark.capture.capture import Capture
from pyshark.tshark.tshark import get_tshark_path


class FileCapture(Capture):
    """
    A class representing a capture read from a file.
    """

    def __init__(self, input_file=None):
        """
        Creates a packet capture object by reading from file.

        :param input_file: Either a path or a file-like object containing either a packet capture file (PCAP, PCAP-NG..)
        or a TShark xml.
        """
        super(FileCapture, self).__init__()
        if isinstance(input_file, basestring):
            self.input_file = file(input_file, 'rb')
        else:
            self.input_file = input_file

        self.packets = self.packets_from_file(self.input_file)

    def close(self):
        if not self.input_file.closed:
            self.input_file.close()

    def packets_from_file(self, cap_or_xml):
        """
        Gets an xml file data and returns the raw xml and a list of packets.

        :return tuple of (raw_xml_file, packets)
        """
        beginning = cap_or_xml.read(5)
        if beginning == '<?xml':
            # It's an xml file.
            return list(self._packets_from_fd(cap_or_xml, previous_data=beginning, wait_for_more_data=False))
        else:
            # We assume it's a PCAP file and use tshark to get the XML.
            p = subprocess.Popen([get_tshark_path(),
                      '-T', 'pdml',
                      '-r', cap_or_xml.name],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
            return list(self._packets_from_fd(p.stdout, previous_data=beginning, wait_for_more_data=False))

    def __repr__(self):
        return '<%s %s (%d packets)>' %(self.__class__.__name__, self.filename, len(self.packets))

    @property
    def filename(self):
        """
        Returns the filename of the capture file represented by this object.
        """
        return self.input_file.name