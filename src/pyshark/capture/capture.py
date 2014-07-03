import os
import subprocess
import sys
from pyshark.tshark.tshark import get_tshark_path
from pyshark.tshark.tshark_xml import packet_from_xml_packet, psml_structure_from_xml


class TSharkCrashException(Exception):
    pass


class Capture(object):
    """
    Base class for packet captures.
    """

    def __init__(self, display_filter=None, only_summaries=False):
        self._packets = []
        self.current_packet = 0
        self.display_filter = display_filter
        self.only_summaries = only_summaries
        self.tshark_process = None

    def __getitem__(self, item):
        """
        Gets the packet in the given index.

        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    def __len__(self):
        return len(self._packets)
    
    def next(self):
        return self.next_packet()
    
    # Allows for child classes to call next() from super() without 2to3 "fixing"
    # the call
    def next_packet(self):
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
    def _extract_tag_from_data(data, tag_name='packet'):
        """
        Gets data containing a (part of) tshark xml.
        If the given tag is found in it, returns the tag data and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark xml.
        :return: a tuple of (tag, data). tag will be None if none is found.
        """
        opening_tag, closing_tag = b'<%s>' % tag_name, b'</%s>' % tag_name
        tag_end = data.find(closing_tag)
        if tag_end != -1:
            tag_end += len(closing_tag)
            tag_start = data.find(opening_tag)
            return data[tag_start:tag_end], data[tag_end:]
        return None, data

    def _packets_from_fd(self, fd, previous_data=b'', packet_count=None, wait_for_more_data=True, batch_size=4096):
        """
        Reads packets from a file-like object containing a TShark XML.
        Returns a generator.

        :param fd: A file-like object containing a TShark XML
        :param previous_data: Any data to put before the file.
        :param packet_count: A maximum amount of packets to stop after.
        :param wait_for_more_data: Whether to wait for more data or stop when
            none is available (i.e. when the fd is a standard file)
        """
        data = previous_data
        packets_captured = 0
        psml_struct = None

        if self.only_summaries:
            # If summaries are read, we need the psdml structure which appears on top of the file.
            while not psml_struct:
                data += fd.read(batch_size)
                psml_struct, data = self._extract_tag_from_data(data, 'structure')
                psml_struct = psml_structure_from_xml(psml_struct)

        while True:
            # Read data until we get a packet, and yield it.
            new_data = fd.read(batch_size)
            data += new_data
            packet, data = self._extract_tag_from_data(data)

            if packet:
                packets_captured += 1
                yield packet_from_xml_packet(packet, psml_structure=psml_struct)

            if packet is None and not wait_for_more_data and len(new_data) < batch_size:
                break

            if packet_count and packets_captured >= packet_count:
                break
    
    def _set_tshark_process(self, packet_count=None, extra_params=[]):
        """
        Sets the internal tshark to a new tshark process with the previously-set paramaters.
        """
        xml_type = 'psml' if self.only_summaries else 'pdml'
        parameters = [get_tshark_path(), '-T', xml_type] + self.get_parameters(packet_count=packet_count) + extra_params
        # Re-direct TShark's stderr to the null device
        self.tshark_stderr = open(os.devnull, "wb")
        # Start the TShark subprocess
        self.tshark_process = subprocess.Popen(parameters,
                                               stdout=subprocess.PIPE,
                                               stderr=self.tshark_stderr)
        retcode = self.tshark_process.poll()
        if retcode is not None and retcode != 0:
            raise TSharkCrashException('TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
    
    def _cleanup_subprocess(self):
        try:
            self.tshark_process.terminate()
        except OSError:
            if 'win' not in sys.platform:
                raise
        self.tshark_process.stdout.close()
        self.tshark_stderr.close()
        self.tshark_process = None
        
    
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