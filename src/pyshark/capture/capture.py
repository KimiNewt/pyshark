import asyncio
import os
import threading
import subprocess
import concurrent.futures
from distutils.version import LooseVersion

import logbook
import sys

from logbook import StreamHandler

from pyshark.tshark.tshark import get_process_path, get_tshark_display_filter_flag, \
    tshark_supports_json, TSharkVersionException, get_tshark_version
from pyshark.tshark.tshark_json import packet_from_json_packet
from pyshark.tshark.tshark_xml import packet_from_xml_packet, psml_structure_from_xml


class TSharkCrashException(Exception):
    pass


class UnknownEncyptionStandardException(Exception):
    pass


class RawMustUseJsonException(Exception):
    """If the use_raw argument is True, so should the use_json argument"""


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
                 override_prefs=None, capture_filter=None, use_json=False, include_raw=False,
                 custom_parameters=None):

        self.loaded = False
        self.tshark_path = tshark_path
        self._override_prefs = override_prefs
        self.debug = False
        self.use_json = use_json
        self.include_raw = include_raw
        self._packets = []
        self._current_packet = 0
        self._display_filter = display_filter
        self._capture_filter = capture_filter
        self._only_summaries = only_summaries
        self._output_file = output_file
        self._running_processes = set()
        self._decode_as = decode_as
        self._disable_protocol = disable_protocol
        self._log = logbook.Logger(self.__class__.__name__, level=self.DEFAULT_LOG_LEVEL)
        self._closed = False
        self._custom_parameters = custom_parameters
        self._tshark_version = None

        if include_raw and not use_json:
            raise RawMustUseJsonException("use_json must be True if include_raw")

        self.eventloop = eventloop
        if self.eventloop is None:
            self._setup_eventloop()
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
        if self._current_packet >= len(self._packets):
            raise StopIteration()
        cur_packet = self._packets[self._current_packet]
        self._current_packet += 1
        return cur_packet

    def clear(self):
        """Empties the capture of any saved packets."""
        self._packets = []
        self._current_packet = 0

    def reset(self):
        """
        Starts iterating packets from the first one.
        """
        self._current_packet = 0

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
                raise StopCapture()

        try:
            self.apply_on_packets(keep_packet, timeout=timeout)
            self.loaded = True
        except concurrent.futures.TimeoutError:
            pass

    def set_debug(self, set_to=True):
        """
        Sets the capture to debug mode (or turns it off if specified).
        """
        if set_to:
            StreamHandler(sys.stdout).push_application()
            self._log.level = logbook.DEBUG
        self.debug = set_to

    def _setup_eventloop(self):
        """
        Sets up a new eventloop as the current one according to the OS.
        """
        if os.name == 'nt':
            self.eventloop = asyncio.ProactorEventLoop()
        else:
            self.eventloop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.eventloop)
        if os.name == 'posix' and isinstance(threading.current_thread(), threading._MainThread):
            asyncio.get_child_watcher().attach_loop(self.eventloop)

    def _get_json_separators(self):
        """"Returns the separators between packets in a JSON output

        Returns a tuple of (packet_separator, end_of_file_separator, characters_to_disregard).
        The latter variable being the number of characters to ignore in order to pass the packet (i.e. extra newlines,
        commas, parenthesis).
        """
        if LooseVersion(self._tshark_version) >= LooseVersion("3.0.0"):
            return ("%s  },%s" % (os.linesep, os.linesep)).encode(), ("}%s]" % os.linesep).encode(), (
                    1 + len(os.linesep))
        else:
            return ("}%s%s  ," % (os.linesep, os.linesep)).encode(), ("}%s%s]" % (os.linesep, os.linesep)).encode(), 1

    def _extract_packet_json_from_data(self, data, got_first_packet=True):
        tag_start = 0
        if not got_first_packet:
            tag_start = data.find(b"{")
            if tag_start == -1:
                return None, data
        packet_separator, end_separator, end_tag_strip_length = self._get_json_separators()
        found_separator = None

        tag_end = data.find(packet_separator)
        if tag_end == -1:
            # Not end of packet, maybe it has end of entire file?
            tag_end = data.find(end_separator)
            if tag_end != -1:
                found_separator = end_separator
        else:
            # Found a single packet, just add the separator without extras
            found_separator = packet_separator

        if found_separator:
            tag_end += len(found_separator) - end_tag_strip_length
            return data[tag_start:tag_end], data[tag_end + 1:]
        return None, data

    def _extract_tag_from_data(self, data, tag_name=b'packet'):
        """Gets data containing a (part of) tshark xml.

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
            if tshark_process in self._running_processes:
                self.eventloop.run_until_complete(self._cleanup_subprocess(tshark_process))

    def apply_on_packets(self, callback, timeout=None, packet_count=None):
        """
        Runs through all packets and calls the given callback (a function) with each one as it is read.
        If the capture is infinite (i.e. a live capture), it will run forever, otherwise it will complete after all
        packets have been read.

        Example usage:
        def print_callback(pkt):
            print(pkt)
        capture.apply_on_packets(print_callback)

        If a timeout is given, raises a Timeout error if not complete before the timeout (in seconds)
        """
        coro = self.packets_from_tshark(callback, packet_count=packet_count)
        if timeout is not None:
            coro = asyncio.wait_for(coro, timeout)
        return self.eventloop.run_until_complete(coro)

    async def packets_from_tshark(self, packet_callback, packet_count=None, close_tshark=True):
        """
        A coroutine which creates a tshark process, runs the given callback on each packet that is received from it and
        closes the process when it is done.

        Do not use interactively. Can be used in order to insert packets into your own eventloop.
        """
        tshark_process = await self._get_tshark_process(packet_count=packet_count)
        try:
            await self._go_through_packets_from_fd(tshark_process.stdout, packet_callback, packet_count=packet_count)
        except StopCapture:
            pass
        finally:
            if close_tshark:
                await self._close_async()
                #yield From(self._cleanup_subprocess(tshark_process))

    async def _go_through_packets_from_fd(self, fd, packet_callback, packet_count=None):
        """A coroutine which goes through a stream and calls a given callback for each XML packet seen in it."""
        packets_captured = 0
        self._log.debug('Starting to go through packets')

        psml_struct, data = await self._get_psml_struct(fd)

        while True:
            try:
                packet, data = await self._get_packet_from_stream(fd, data, got_first_packet=packets_captured > 0,
                                                                  psml_structure=psml_struct)
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

    async def _get_psml_struct(self, fd):
        """Gets the current PSML (packet summary xml) structure in a tuple ((None, leftover_data)),
        only if the capture is configured to return it, else returns (None, leftover_data).

        A coroutine.
        """
        data = b''
        psml_struct = None

        if self._only_summaries:
            # If summaries are read, we need the psdml structure which appears on top of the file.
            while not psml_struct:
                new_data = await fd.read(self.SUMMARIES_BATCH_SIZE)
                data += new_data
                psml_struct, data = self._extract_tag_from_data(data, b'structure')
                if psml_struct:
                    psml_struct = psml_structure_from_xml(psml_struct)
                elif not new_data:
                    return None, data
            return psml_struct, data
        else:
            return None, data

    async def _get_packet_from_stream(self, stream, existing_data, got_first_packet=True, psml_structure=None):
        """A coroutine which returns a single packet if it can be read from the given StreamReader.

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
            return packet, existing_data

        new_data = await stream.read(self.DEFAULT_BATCH_SIZE)
        existing_data += new_data

        if not new_data:
            # Reached EOF
            raise EOFError()
        return None, existing_data

    def _get_tshark_path(self):
        return get_process_path(self.tshark_path)

    def _stderr_output(self):
        # Ignore stderr output unless in debug mode (sent to console)
        return None if self.debug else open(os.devnull, "w")

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        """
        Returns a new tshark process with previously-set parameters.
        """
        if self.use_json:
            output_type = 'json'
            if not self._tshark_version:
                self._tshark_version = get_tshark_version(self.tshark_path)
            if not tshark_supports_json(self._tshark_version):
                raise TSharkVersionException("JSON only supported on Wireshark >= 2.2.0")
        else:
            output_type = 'psml' if self._only_summaries else 'pdml'
        parameters = [self._get_tshark_path(), '-l', '-n', '-T', output_type] + \
            self.get_parameters(packet_count=packet_count)

        self._log.debug('Creating TShark subprocess with parameters: ' + ' '.join(parameters))
        self._log.debug('Executable: %s' % parameters[0])
        tshark_process = await asyncio.create_subprocess_exec(*parameters,
                                                              stdout=subprocess.PIPE,
                                                              stderr=self._stderr_output(),
                                                              stdin=stdin)
        self._created_new_process(parameters, tshark_process)
        return tshark_process

    def _created_new_process(self, parameters, process, process_name="TShark"):
        self._log.debug(process_name + ' subprocess created')
        if process.returncode is not None and process.returncode != 0:
            raise TSharkCrashException(
                '%s seems to have crashed. Try updating it. (command ran: "%s")' % (
                    process_name, ' '.join(parameters)))
        self._running_processes.add(process)

    async def _cleanup_subprocess(self, process):
        """
        Kill the given process and properly closes any pipes connected to it.
        """
        if process.returncode is None:
            try:
                process.kill()
                return await asyncio.wait_for(process.wait(), 1)
            except concurrent.futures.TimeoutError:
                self._log.debug('Waiting for process to close failed, may have zombie process.')
            except ProcessLookupError:
                pass
            except OSError:
                if os.name != 'nt':
                    raise
        elif process.returncode > 0:
            raise TSharkCrashException('TShark seems to have crashed (retcode: %d). '
                                       'Try rerunning in debug mode [ capture_obj.set_debug() ] or try updating tshark.'
                                       % process.returncode)

    def close(self):
        self.eventloop.run_until_complete(self._close_async())

    async def _close_async(self):
        for process in self._running_processes.copy():
            await self._cleanup_subprocess(process)
        self._running_processes.clear()

    def __del__(self):
        if self._running_processes:
            self.close()

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = []
        if self._capture_filter:
            params += ['-f', self._capture_filter]
        if self._display_filter:
            params += [get_tshark_display_filter_flag(self.tshark_path), self._display_filter]
        # Raw is only enabled when JSON is also enabled.
        if self.include_raw:
            params += ["-x"]
        if packet_count:
            params += ['-c', str(packet_count)]

        if self._custom_parameters:
            if isinstance(self._custom_parameters, list):
                params += self._custom_parameters
            elif isinstance(self._custom_parameters, dict):
                for key, val in self._custom_parameters.items():
                    params += [key, val]
            else:
                raise Exception("Custom parameters type not supported.")

        if all(self.encryption):
            params += ['-o', 'wlan.enable_decryption:TRUE', '-o', 'uat:80211_keys:"' + self.encryption[1] + '","' +
                                                                  self.encryption[0] + '"']
        if self._override_prefs:
            for preference_name, preference_value in self._override_prefs.items():
                if all(self.encryption) and preference_name in ('wlan.enable_decryption', 'uat:80211_keys'):
                    continue  # skip if override preferences also given via --encryption options
                params += ['-o', '{0}:{1}'.format(preference_name, preference_value)]

        if self._output_file:
            params += ['-w', self._output_file]

        if self._decode_as:
            for criterion, decode_as_proto in self._decode_as.items():
                params += ['-d', ','.join([criterion.strip(), decode_as_proto.strip()])]

        if self._disable_protocol:
            params += ['--disable-protocol', self._disable_protocol.strip()]

        return params

    def __iter__(self):
        if self.loaded:
            return iter(self._packets)
        else:
            return self._packets_from_tshark_sync()

    def __repr__(self):
        return '<%s (%d packets)>' % (self.__class__.__name__, len(self._packets))
