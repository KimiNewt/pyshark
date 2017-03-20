from __future__ import unicode_literals
import os
import logbook
import sys

import trollius as asyncio
from logbook import StreamHandler
from trollius import From, subprocess, Return
from trollius.executor import TimeoutError
from trollius.py33_exceptions import ProcessLookupError

from pyshark.tshark.tshark import get_tshark_path, get_tshark_display_filter_flag, \
    tshark_supports_json, TSharkVersionException
from pyshark.tshark.tshark_json import packet_from_json_packet
from pyshark.tshark.tshark_xml import packet_from_xml_packet, psml_structure_from_xml


class TSharkCrashException(Exception):
    pass


class UnknownEncyptionStandardException(Exception):
    pass


class StopCapture(Exception):
    """
    Exception that the user can throw anywhere in packet-handling to stop the capture process.
    """
    pass


class Capture(object):
    """
    Base class for packet captures.
    """
    DEFAULT_BATCH_SIZE = 2 ** 16
    SUMMARIES_BATCH_SIZE = 64
    DEFAULT_LOG_LEVEL = logbook.CRITICAL
    SUPPORTED_ENCRYPTION_STANDARDS = ['wep', 'wpa-pwk', 'wpa-pwd', 'wpa-psk']

    def __init__(self, display_filter=None, only_summaries=False, eventloop=None,
                 decryption_key=None, encryption_type='wpa-pwd', output_file=None,
                 decode_as=None,  disable_protocol=None, tshark_path=None,
                 override_prefs=None, capture_filter=None, use_json=False):
        self._packets = []
        self.current_packet = 0
        self.display_filter = display_filter
        self.capture_filter = capture_filter
        self.only_summaries = only_summaries
        self.output_file = output_file
        self.running_processes = set()
        self.loaded = False
        self.decode_as = decode_as
        self.disable_protocol = disable_protocol
        self._log = logbook.Logger(self.__class__.__name__, level=self.DEFAULT_LOG_LEVEL)
        self.tshark_path = tshark_path
        self.override_prefs = override_prefs
        self.debug = False
        self.use_json = use_json

        self.eventloop = eventloop
        if self.eventloop is None:
            self.setup_eventloop()
        if encryption_type and encryption_type.lower() in self.SUPPORTED_ENCRYPTION_STANDARDS:
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnknownEncyptionStandardException("Only the following standards are supported: %s."
                                                    % ', '.join(self.SUPPORTED_ENCRYPTION_STANDARDS))

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
        If 0 as the packet_count is given, reads forever

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
            self.loaded = True
        except TimeoutError:
            pass

    def set_debug(self, set_to=True):
        """
        Sets the capture to debug mode (or turns it off if specified).
        """
        if set_to:
            StreamHandler(sys.stdout).push_application()
            self._log.level = logbook.DEBUG
        self.debug = set_to

    def setup_eventloop(self):
        """
        Sets up a new eventloop as the current one according to the OS.
        """
        if os.name == 'nt':
            self.eventloop = asyncio.ProactorEventLoop()
            if sys.version_info <= (3, 0):
                # FIXME: There appears to be a bug in the 2.7 version of trollius, wherein the selector retrieves an
                # object of value 0 and attempts to look for it in the weakref set, which raises an exception.
                # This hack sidesteps this issue, but does not solve it. If a proper fix is found, apply it!
                self.eventloop._selector._stopped_serving = set()
        else:
            self.eventloop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.eventloop)

    @staticmethod
    def _extract_packet_json_from_data(data, got_first_packet=True):
        tag_start = 0
        if not got_first_packet:
            tag_start = data.find(b"{")
            if tag_start == -1:
                return None, data
        closing_tag = b"}\n\n  ,"
        tag_end = data.find(closing_tag)
        if tag_end == -1:
            closing_tag = b"}\n\n]"
            tag_end = data.find(closing_tag)
        if tag_end != -1:
            # Include closing parenthesis but not comma
            tag_end += len(closing_tag) - 1
            return data[tag_start:tag_end], data[tag_end + 1:]
        return None, data

    @staticmethod
    def _extract_tag_from_data(data, tag_name=b'packet'):
        """
        Gets data containing a (part of) tshark xml.
        If the given tag is found in it, returns the tag data and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark xml.
        :return: a tuple of (tag, data). tag will be None if none is found.
        """
        opening_tag = b'<' + tag_name + b'>'
        closing_tag = opening_tag.replace(b'<', b'</')
        tag_end = data.find(closing_tag)
        if tag_end != -1:
            tag_end += len(closing_tag)
            tag_start = data.find(opening_tag)
            return data[tag_start:tag_end], data[tag_end:]
        return None, data

    def _packets_from_tshark_sync(self, packet_count=None, existing_process=None):
        """
        Returns a generator of packets.
        This is the sync version of packets_from_tshark. It wait for the completion of each coroutine and
         reimplements reading packets in a sync way, yielding each packet as it arrives.

        :param packet_count: If given, stops after this amount of packets is captured.
        """
        # NOTE: This has code duplication with the async version, think about how to solve this
        tshark_process = existing_process or self.eventloop.run_until_complete(self._get_tshark_process())
        psml_structure, data = self.eventloop.run_until_complete(self._get_psml_struct(tshark_process.stdout))
        packets_captured = 0

        data = b''
        try:
            while True:
                try:
                    packet, data = self.eventloop.run_until_complete(
                        self._get_packet_from_stream(tshark_process.stdout, data, psml_structure=psml_structure,
                                                     got_first_packet=packets_captured > 0))

                except EOFError:
                    self._log.debug('EOF reached (sync)')
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
            coro = asyncio.wait_for(coro, timeout)
        return self.eventloop.run_until_complete(coro)

    @asyncio.coroutine
    def packets_from_tshark(self, packet_callback, packet_count=None, close_tshark=True):
        """
        A coroutine which creates a tshark process, runs the given callback on each packet that is received from it and
        closes the process when it is done.

        Do not use interactively. Can be used in order to insert packets into your own eventloop.
        """
        tshark_process = yield From(self._get_tshark_process(packet_count=packet_count))
        try:
            yield From(self._go_through_packets_from_fd(tshark_process.stdout, packet_callback,
                                                        packet_count=packet_count))
        except StopCapture:
            pass
        finally:
            if close_tshark:
                self._cleanup_subprocess(tshark_process)

    @asyncio.coroutine
    def _go_through_packets_from_fd(self, fd, packet_callback, packet_count=None):
        """
        A coroutine which goes through a stream and calls a given callback for each XML packet seen in it.
        """
        packets_captured = 0
        self._log.debug('Starting to go through packets')

        psml_struct, data = yield From(self._get_psml_struct(fd))
        while True:
            try:
                packet, data = yield From(self._get_packet_from_stream(fd, data,
                                                                       got_first_packet=packets_captured > 0,
                                                                       psml_structure=psml_struct))
            except EOFError:
                self._log.debug('EOF reached')
                break

            if packet:
                packets_captured += 1
                try:
                    packet_callback(packet)
                except StopCapture:
                    self._log.debug('User-initiated capture stop in callback')
                    break

            if packet_count and packets_captured >= packet_count:
                break

    @asyncio.coroutine
    def _get_psml_struct(self, fd):
        """
        Gets the current PSML (packet summary xml) structure in a tuple ((None, leftover_data)),
        only if the capture is configured to return it, else returns (None, leftover_data).

        A coroutine.
        """
        data = b''
        psml_struct = None

        if self.only_summaries:
            # If summaries are read, we need the psdml structure which appears on top of the file.
            while not psml_struct:
                new_data = yield From(fd.read(self.SUMMARIES_BATCH_SIZE))
                data += new_data
                psml_struct, data = self._extract_tag_from_data(data, b'structure')
                if psml_struct:
                    psml_struct = psml_structure_from_xml(psml_struct)
                elif not new_data:
                    raise Return(None, data)
            raise Return(psml_struct, data)
        else:
            raise Return(None, data)

    @asyncio.coroutine
    def _get_packet_from_stream(self, stream, existing_data, got_first_packet=True,
                                psml_structure=None):
        """
        A coroutine which returns a single packet if it can be read from the given StreamReader.
        :return a tuple of (packet, remaining_data). The packet will be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        # yield each packet in existing_data
        if self.use_json:
            packet, existing_data = self._extract_packet_json_from_data(existing_data,
                                                                        got_first_packet=got_first_packet)
        else:
            packet, existing_data = self._extract_tag_from_data(existing_data)

        if packet:
            if self.use_json:
                packet = packet_from_json_packet(packet)
            else:
                packet = packet_from_xml_packet(packet, psml_structure=psml_structure)
            raise Return(packet, existing_data)

        new_data = yield From(stream.read(self.DEFAULT_BATCH_SIZE))
        existing_data += new_data

        if not new_data:
            # Reached EOF
            raise EOFError()
        raise Return(None, existing_data)

    @asyncio.coroutine
    def _get_tshark_process(self, packet_count=None, stdin=None):
        """
        Returns a new tshark process with previously-set parameters.
        """
        if self.use_json:
            output_type = 'json'
            if not tshark_supports_json():
                raise TSharkVersionException("JSON only supported on Wireshark >= 2.2.0")
        else:
            output_type = 'psml' if self.only_summaries else 'pdml'
        parameters = [get_tshark_path(self.tshark_path), '-l', '-n', '-T', output_type] + \
                     self.get_parameters(packet_count=packet_count)

        self._log.debug('Creating TShark subprocess with parameters: ' + ' '.join(parameters))

        # Ignore stderr output unless in debug mode (sent to console)
        output = None if self.debug else open(os.devnull, "w")
        tshark_process = yield From(asyncio.create_subprocess_exec(*parameters,
                                                                   stdout=subprocess.PIPE,
                                                                   stderr=output,
                                                                   stdin=stdin))
        self._log.debug('TShark subprocess created')

        if tshark_process.returncode is not None and tshark_process.returncode != 0:
            raise TSharkCrashException(
                'TShark seems to have crashed. Try updating it. (command ran: "%s")' % ' '.join(parameters))
        self.running_processes.add(tshark_process)
        raise Return(tshark_process)

    def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected to it.
        """
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                if os.name != 'nt':
                    raise
        elif process.returncode > 0:
            raise TSharkCrashException('TShark seems to have crashed (retcode: %d). Try rerunning in debug mode [ capture_obj.set_debug() ] or try updating tshark.' % process.returncode)

    def close(self):
        for process in self.running_processes:
            self._cleanup_subprocess(process)

    def __del__(self):
        self.close()

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = []
        if self.capture_filter:
            params += ['-f', self.capture_filter]
        if self.display_filter:
            params += [get_tshark_display_filter_flag(self.tshark_path), self.display_filter]
        if packet_count:
            params += ['-c', str(packet_count)]
        if all(self.encryption):
            params += ['-o', 'wlan.enable_decryption:TRUE', '-o', 'uat:80211_keys:"' + self.encryption[1] + '","' +
                                                                  self.encryption[0] + '"']
        if self.override_prefs:
            for preference_name, preference_value in self.override_prefs.items():
                if all(self.encryption) and preference_name in ('wlan.enable_decryption', 'uat:80211_keys'):
                    continue  # skip if override preferences also given via --encryption options
                params += ['-o', '{0}:{1}'.format(preference_name, preference_value)]

        if self.output_file:
            params += ['-w', self.output_file]

        if self.decode_as:
            for criterion, decode_as_proto in self.decode_as.items():
                params += ['-d', ','.join([criterion.strip(), decode_as_proto.strip()])]

        if self.disable_protocol:
            params += ['--disable-protocol', self.disable_protocol.strip()]

        return params

    def __iter__(self):
        if self.loaded:
            return iter(self._packets)
        else:
            return self._packets_from_tshark_sync()

    def __repr__(self):
        return '<%s (%d packets)>' % (self.__class__.__name__, len(self._packets))
