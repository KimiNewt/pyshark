import subprocess
from pyshark.tshark.tshark import get_tshark_path
from pyshark.tshark.tshark_xml import packet_from_xml_packet


class Capture(object):
    """
    Base class for packet captures.
    """

    def __init__(self, display_filter=None):
        self._packets = []
        self.current_packet = 0
        self.display_filter = display_filter

    def __getitem__(self, item):
        """
        Gets the packet in the given index.

        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    def next(self):
        if self.current_packet >= len(self._packets):
            raise StopIteration()
        cur_packet = self._packets[self.current_packet]
        self.current_packet += 1
        return cur_packet

    def clear(self):
        """
        Empties the capture of any saved packets.
        """
        self._packets = []
        self.current_packet = 0

    def reset(self):
        """
        Starts iterating packets from the first one.
        """
        self.current_packet = 0

    @staticmethod
    def _extract_packet_from_data(data):
        """
        Gets data containing a (part of) tshark xml.
        If a packet is found in it, returns the packet and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark xml.
        :return: a tuple of (packet, data). packet will be None if none is found.
        """
        packet_end = data.find('</packet>')
        if packet_end != -1:
            packet_end += len('</packet>')
            packet_start = data.find('<packet>')
            return data[packet_start:packet_end], data[packet_end:]
        return None, data

    @classmethod
    def _packets_from_fd(cls, fd, previous_data='', packet_count=None, wait_for_more_data=True, batch_size=1000):
        """
        Reads packets from a file-like object containing a TShark XML.
        Returns a generator.

        :param fd: A file-like object containing a TShark XML
        :param previous_data: Any data to put before the file.
        :param packet_count: A maximum amount of packets to stop after.
        :param wait_for_more_data: Whether to wait for more data or stop when none is available (i.e. when the fd is a
        standard file)
        """
        data = previous_data
        packets_captured = 0

        while True:
            # Read data until we get a packet, and yield it.
            new_data = fd.read(batch_size)
            data += new_data
            packet, data = cls._extract_packet_from_data(data)

            if packet:
                packets_captured += 1
                yield packet_from_xml_packet(packet)

            if not wait_for_more_data and len(new_data) < batch_size:
                break

            if packet_count and packets_captured >= packet_count:
                break

    def _get_tshark_process(self, packet_count=None, extra_params=[]):
        """
        Gets a new tshark process with the previously-set paramaters.
        """
        parameters = [get_tshark_path(), '-T', 'pdml'] + self.get_parameters(packet_count=packet_count) + extra_params
        return subprocess.Popen(parameters,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = []
        if self.display_filter:
            params += ['-R', self.display_filter]
        if packet_count:
            params += ['-c', str(packet_count)]
        return params

    def __iter__(self):
        while True:
            yield self.next()

    def __repr__(self):
        return '<%s (%d packets)>' %(self.__class__.__name__, len(self._packets))