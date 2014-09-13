from distutils.version import LooseVersion
import os
import logbook
import trollius
from trollius import From, subprocess, Return
from trollius.py33_exceptions import ProcessLookupError

from pyshark.tshark.tshark import get_tshark_path, get_tshark_version
from pyshark.tshark.tshark_xml import packet_from_xml_packet, psml_structure_from_xml

if os.name == 'nt':
    loop = trollius.ProactorEventLoop()
    trollius.set_event_loop(loop)
else:
    loop = trollius.get_event_loop()


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
        self.log = logbook.Logger(self.__class__.__name__)

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

    def load_packets(self, packet_count=0, timeout=None):
        """
        Reads the packets from the source (cap, interface, etc.) and adds it to the internal list.
        If 0 as the is given, reads forever

        :param packet_count: The amount of packets to add to the packet list (0 to read forever)
        :param timeout: If given, automatically stops after a given amount of time.
        """
        # TODO: Implement timeout
        initial_packet_amount = len(self._packets)
        def keep_packet(pkt):
            self._packets.append(pkt)

            if packet_count != 0 and len(self._packets) - initial_packet_amount >= packet_count:
                raise Return()

        self.apply_on_packets(keep_packet)

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

    def _packets_from_tshark_sync(self):
        """
        Returns a generator of packets.
        """
        # NOTE: This has code duplication with the async version, think about how to solve this
        # TODO: Add packet summary stuff + handle parameters
        tshark_process = loop.run_until_complete(self._get_tshark_process())
        data = ''

        try:
            while True:
                try:
                    packet, data = loop.run_until_complete(self._get_packet_from_stream(tshark_process.stdout, data))
                except EOFError:
                    self.log.debug('EOF reached (sync)')
                    break
                if packet:
                    yield packet
        finally:
            self._cleanup_subprocess(tshark_process)

    def apply_on_packets(self, callback):
        """
        Runs through all packets and calls the given callback (a function) with each one as it is read.
        If the capture is infinite (i.e. a live capture), it will run forever, otherwise it will complete after all
        packets have been read.

        Example usage:
        def print_callback(pkt):
            print pkt
        capture.apply_on_packets(print_callback)
        """
        return loop.run_until_complete(self._packets_from_tshark(callback))

    @trollius.coroutine
    def _packets_from_tshark(self, packet_callback, packet_count=None, batch_size=4096):
        """
        A coroutine which creates a tshark process, runs the given callback on each packet that is received from it and
        closes the process when it is done.
        """
        tshark_process = yield From(self._get_tshark_process(packet_count=packet_count))
        try:
            yield From(self._go_through_packets_from_fd(tshark_process.stdout, packet_callback,
                                                        packet_count=packet_count, batch_size=batch_size))
        finally:
            self._cleanup_subprocess(tshark_process)

    @trollius.coroutine
    def _go_through_packets_from_fd(self, fd, packet_callback, previous_data=b'', packet_count=None, batch_size=4096):
        """
        A coroutine which goes through a stream and calls a given callback for each XML packet seen in it.
        """
        data = previous_data
        packets_captured = 0
        psml_struct = None
        self.log.debug('Starting to go through packets')

        if self.only_summaries:
            # If summaries are read, we need the psdml structure which appears on top of the file.
            while not psml_struct:
                data += yield From(fd.read(batch_size))
                psml_struct, data = self._extract_tag_from_data(data, 'structure')
                psml_struct = psml_structure_from_xml(psml_struct)

        while True:
            try:
                packet, data = yield From(self._get_packet_from_stream(fd, data,
                                                                batch_size=batch_size, psml_structure=psml_struct))
            except EOFError:
                self.log.debug('EOF reached')
                break

            if packet:
                self.log.debug('Packet captured')
                packets_captured += 1
                packet_callback(packet)

            if packet_count and packets_captured >= packet_count:
                break

    @trollius.coroutine
    def _get_packet_from_stream(self, stream, existing_data, batch_size=4096, psml_structure=None):
        """
        A coroutine which returns a single packet if it can be read from the given StreamReader.
        :return a tuple of (packet, remaining_data). The packet will be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        # Read data until we get a packet, and yield it.
        new_data = yield From(stream.read(batch_size))
        existing_data += new_data
        packet, existing_data = self._extract_tag_from_data(existing_data)

        if not new_data:
            # Reached EOF
            raise EOFError()

        if packet:
            self.log.debug('Packet captured')
            packet = packet_from_xml_packet(packet, psml_structure=psml_structure)
            raise Return(packet, existing_data)
        raise Return(None, existing_data)

    @trollius.coroutine
    def _get_tshark_process(self, packet_count=None):
        """
        Returns a new tshark process with previously-set parameters.
        """
        xml_type = 'psml' if self.only_summaries else 'pdml'
        parameters = [get_tshark_path(), '-T', xml_type] + self.get_parameters(packet_count=packet_count)

        self.log.debug('Creating TShark subprocess with parameters: ' + ' '.join(parameters))
        tshark_process = yield From(trollius.create_subprocess_exec(*parameters,
                                                                    stdout=subprocess.PIPE,
                                                                    stderr=open(os.devnull, "wb")))
        self.log.debug('TShark subprocess created')

        if tshark_process.returncode is not None and self.tshark_process.returncode != 0:
            raise TSharkCrashException(
                'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
        raise Return(tshark_process)

    def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected to it.
        """
        try:
            process.kill()
        except ProcessLookupError:
            pass

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        tshark_version = get_tshark_version()
        if LooseVersion(tshark_version) >= LooseVersion("1.10.0"):
            display_filter_flag = '-Y'
        else:
            display_filter_flag = '-R'

        params = []
        if self.display_filter:
            params += [display_filter_flag, self.display_filter]
        if packet_count:
            params += ['-c', str(packet_count)]
        return params

    def __iter__(self):
        return self._packets_from_tshark_sync

    def __repr__(self):
        return '<%s (%d packets)>' % (self.__class__.__name__, len(self._packets))