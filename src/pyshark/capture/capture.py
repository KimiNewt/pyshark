from distutils.version import LooseVersion
import os
import logbook
import trollius
from trollius import From, subprocess, Return
from trollius.executor import TimeoutError
from trollius.py33_exceptions import ProcessLookupError

from pyshark.tshark.tshark import get_tshark_path, get_tshark_version
from pyshark.tshark.tshark_xml import packet_from_xml_packet, psml_structure_from_xml


class TSharkCrashException(Exception):
    pass


class Capture(object):
    """
    Base class for packet captures.
    """
    DEFAULT_BATCH_SIZE = 4096
    SUMMARIES_BATCH_SIZE = 32

    def __init__(self, display_filter=None, only_summaries=False, eventloop=None):
        self._packets = []
        self.current_packet = 0
        self.display_filter = display_filter
        self.only_summaries = only_summaries
        self.tshark_process = None
        self.running_processes = set()
        self.log = logbook.Logger(self.__class__.__name__)

        self.eventloop = eventloop
        if self.eventloop is None:
            self.setup_eventloop()

    def setup_eventloop(self):
        """
        Sets up a new eventloop as the current one according to the OS.
        """
        if os.name == 'nt':
            self.eventloop = trollius.ProactorEventLoop()
            trollius.set_event_loop(self.eventloop)
        else:
            self.eventloop = trollius.get_event_loop()

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
        initial_packet_amount = len(self._packets)
        def keep_packet(pkt):
            self._packets.append(pkt)

            if packet_count != 0 and len(self._packets) - initial_packet_amount >= packet_count:
                raise Return()

        try:
            self.apply_on_packets(keep_packet, timeout=timeout)
        except TimeoutError:
            pass

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

    def _packets_from_tshark_sync(self, packet_count=None):
        """
        Returns a generator of packets.
        This is the sync version of packets_from_tshark. It wait for the completion of each coroutine and
         reimplements reading packets in a sync way, yielding each packet as it arrives.

        :param packet_count: If given, stops after this amount of packets is captured.
        """
        # NOTE: This has code duplication with the async version, think about how to solve this
        tshark_process = self.eventloop.run_until_complete(self._get_tshark_process())
        psml_structure = self.eventloop.run_until_complete(self._get_psml_struct(tshark_process.stdout))
        packets_captured = 0

        data = ''
        try:
            while True:
                try:
                    packet, data = self.eventloop.run_until_complete(
                        self._get_packet_from_stream(tshark_process.stdout, data, psml_structure=psml_structure))
                except EOFError:
                    self.log.debug('EOF reached (sync)')
                    break
                if packet:
                    packets_captured += 1
                    yield packet
                if packet_count and packets_captured >= packet_count:
                    break
        finally:
            self._cleanup_subprocess(tshark_process)

    def apply_on_packets(self, callback, timeout=None):
        """
        Runs through all packets and calls the given callback (a function) with each one as it is read.
        If the capture is infinite (i.e. a live capture), it will run forever, otherwise it will complete after all
        packets have been read.

        Example usage:
        def print_callback(pkt):
            print pkt
        capture.apply_on_packets(print_callback)

        If a timeout is given, raises a Timeout error if not complete before the timeout (in seconds)
        """
        coro = self.packets_from_tshark(callback)
        if timeout is not None:
            coro = trollius.wait_for(coro, timeout)
        try:
            return self.eventloop.run_until_complete(coro)
        finally:
            self.eventloop.stop()
            self.setup_eventloop()

    @trollius.coroutine
    def packets_from_tshark(self, packet_callback, packet_count=None):
        """
        A coroutine which creates a tshark process, runs the given callback on each packet that is received from it and
        closes the process when it is done.

        Do not use directly. Can be used in order to insert packets into your own eventloop.
        """
        tshark_process = yield From(self._get_tshark_process(packet_count=packet_count))
        try:
            yield From(self._go_through_packets_from_fd(tshark_process.stdout, packet_callback,
                                                        packet_count=packet_count))
        finally:
            self._cleanup_subprocess(tshark_process)

    @trollius.coroutine
    def _go_through_packets_from_fd(self, fd, packet_callback, packet_count=None):
        """
        A coroutine which goes through a stream and calls a given callback for each XML packet seen in it.
        """
        data = ''
        packets_captured = 0
        self.log.debug('Starting to go through packets')

        psml_struct = yield From(self._get_psml_struct(fd))

        while True:
            try:
                packet, data = yield From(self._get_packet_from_stream(fd, data, psml_structure=psml_struct))
            except EOFError:
                self.log.debug('EOF reached')
                break

            if packet:
                packets_captured += 1
                packet_callback(packet)

            if packet_count and packets_captured >= packet_count:
                break

    @trollius.coroutine
    def _get_psml_struct(self, fd):
        """
        Gets the current PSML (packet summary xml) structure, if the capture is configured to return it, else
        returns None.

        A coroutine.
        """
        psml_struct = None
        if self.only_summaries:
            # If summaries are read, we need the psdml structure which appears on top of the file.
            while not psml_struct:
                data += yield From(fd.read(self.SUMMARIES_BATCH_SIZE))
                psml_struct, data = self._extract_tag_from_data(data, 'structure')
                psml_struct = psml_structure_from_xml(psml_struct)
            raise Return(psml_struct)
        else:
            raise Return(None)

    @trollius.coroutine
    def _get_packet_from_stream(self, stream, existing_data, psml_structure=None):
        """
        A coroutine which returns a single packet if it can be read from the given StreamReader.
        :return a tuple of (packet, remaining_data). The packet will be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        # Read data until we get a packet, and yield it.
        new_data = yield From(stream.read(self.DEFAULT_BATCH_SIZE))
        existing_data += new_data
        packet, existing_data = self._extract_tag_from_data(existing_data)

        if not new_data:
            # Reached EOF
            raise EOFError()

        if packet:
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
                                                                    stderr=open(os.devnull, "w")))
        self.log.debug('TShark subprocess created')

        if tshark_process.returncode is not None and self.tshark_process.returncode != 0:
            raise TSharkCrashException(
                'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
        self.running_processes.add(tshark_process)
        raise Return(tshark_process)

    def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected to it.
        """
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            if os.name != 'nt':
                raise

    def close(self):
        for process in self.running_processes:
            self._cleanup_subprocess(process)

    def __del__(self):
        self.close()

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