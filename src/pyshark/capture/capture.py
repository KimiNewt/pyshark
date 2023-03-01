import asyncio
import os
import threading
import subprocess
import concurrent.futures
import sys
import logging
import warnings

from pyshark import ek_field_mapping
from pyshark.packet.packet import Packet
from pyshark.tshark.output_parser import tshark_ek
from pyshark.tshark.output_parser import tshark_json
from pyshark.tshark.output_parser import tshark_xml
from pyshark.tshark.tshark import get_process_path, get_tshark_display_filter_flag, \
    tshark_supports_json, TSharkVersionException, get_tshark_version, tshark_supports_duplicate_keys


if sys.version_info < (3, 8):
    asyncTimeoutError = concurrent.futures.TimeoutError
else:
    asyncTimeoutError = asyncio.exceptions.TimeoutError


class TSharkCrashException(Exception):
    pass


class UnknownEncyptionStandardException(Exception):
    pass


class RawMustUseJsonException(Exception):
    """If the use_raw argument is True, so should the use_json argument"""


class StopCapture(Exception):
    """Exception that the user can throw anywhere in packet-handling to stop the capture process."""
    pass


class Capture:
    """Base class for packet captures."""
    SUMMARIES_BATCH_SIZE = 64
    DEFAULT_LOG_LEVEL = logging.CRITICAL
    SUPPORTED_ENCRYPTION_STANDARDS = ["wep", "wpa-pwk", "wpa-pwd", "wpa-psk"]

    def __init__(self, display_filter=None, only_summaries=False, eventloop=None,
                 decryption_key=None, encryption_type="wpa-pwd", output_file=None,
                 decode_as=None,  disable_protocol=None, tshark_path=None,
                 override_prefs=None, capture_filter=None, use_json=False, include_raw=False,
                 use_ek=False, custom_parameters=None, debug=False):

        self.loaded = False
        self.tshark_path = tshark_path
        self._override_prefs = override_prefs
        self.debug = debug
        self.use_json = use_json
        self._use_ek = use_ek
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
        self._log = logging.Logger(
            self.__class__.__name__, level=self.DEFAULT_LOG_LEVEL)
        self._closed = False
        self._custom_parameters = custom_parameters
        self._eof_reached = False
        self._last_error_line = None
        self._stderr_handling_tasks = []
        self.__tshark_version = None

        if include_raw and not (use_json or use_ek):
            raise RawMustUseJsonException(
                "use_json/use_ek must be True if include_raw")

        if self.debug:
            self.set_debug()

        self.eventloop = eventloop
        if self.eventloop is None:
            self._setup_eventloop()
        if encryption_type and encryption_type.lower() in self.SUPPORTED_ENCRYPTION_STANDARDS:
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            standards = ", ".join(self.SUPPORTED_ENCRYPTION_STANDARDS)
            raise UnknownEncyptionStandardException(f"Only the following standards are supported: {standards}.")

    def __getitem__(self, item):
        """Gets the packet in the given index.

        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    def __len__(self):
        return len(self._packets)

    def next(self) -> Packet:
        return self.next_packet()

    # Allows for child classes to call next() from super() without 2to3 "fixing"
    # the call
    def next_packet(self) -> Packet:
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
        """Starts iterating packets from the first one."""
        self._current_packet = 0

    def load_packets(self, packet_count=0, timeout=None):
        """Reads the packets from the source (cap, interface, etc.) and adds it to the internal list.

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
            self.apply_on_packets(
                keep_packet, timeout=timeout, packet_count=packet_count)
            self.loaded = True
        except asyncTimeoutError:
            pass

    def set_debug(self, set_to=True, log_level=logging.DEBUG):
        """Sets the capture to debug mode (or turns it off if specified)."""
        if set_to:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            self._log.addHandler(handler)
            self._log.level = log_level
        self.debug = set_to

    def _verify_capture_parameters(self):
        """Optionally verify that the capture's parameters are valid.

        Should raise an exception if they are not valid.
        """
        pass

    def _setup_eventloop(self):
        """Sets up a new eventloop as the current one according to the OS."""
        if os.name == "nt":
            current_eventloop = asyncio.get_event_loop_policy().get_event_loop()
            if isinstance(current_eventloop, asyncio.ProactorEventLoop):
                self.eventloop = current_eventloop
            else:
                # On Python before 3.8, Proactor is not the default eventloop type, so we have to create a new one.
                # If there was an existing eventloop this can create issues, since we effectively disable it here.
                if asyncio.all_tasks():
                    warnings.warn("The running eventloop has tasks but pyshark must set a new eventloop to continue. "
                                  "Existing tasks may not run.")
                self.eventloop = asyncio.ProactorEventLoop()
                asyncio.set_event_loop(self.eventloop)
        else:
            try:
                self.eventloop = asyncio.get_event_loop_policy().get_event_loop()
            except RuntimeError:
                if threading.current_thread() != threading.main_thread():
                    # Ran not in main thread, make a new eventloop
                    self.eventloop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.eventloop)
                else:
                    raise
            if os.name == "posix" and isinstance(threading.current_thread(), threading._MainThread):
                # The default child watchers (ThreadedChildWatcher) attach_loop method is empty!
                # While using pyshark with ThreadedChildWatcher, asyncio could raise a ChildProcessError
                # "Unknown child process pid %d, will report returncode 255"
                # This led to a TSharkCrashException in _cleanup_subprocess.
                # Using the SafeChildWatcher fixes this issue, but it is slower.
                # SafeChildWatcher O(n) -> large numbers of processes are slow
                # ThreadedChildWatcher O(1) -> independent of process number
                # asyncio.get_child_watcher().attach_loop(self.eventloop)
                asyncio.set_child_watcher(asyncio.SafeChildWatcher())
                asyncio.get_child_watcher().attach_loop(self.eventloop)

    def _packets_from_tshark_sync(self, packet_count=None, existing_process=None):
        """Returns a generator of packets.

        This is the sync version of packets_from_tshark. It wait for the completion of each coroutine and
         reimplements reading packets in a sync way, yielding each packet as it arrives.

        :param packet_count: If given, stops after this amount of packets is captured.
        """
        # NOTE: This has code duplication with the async version, think about how to solve this
        tshark_process = existing_process or self.eventloop.run_until_complete(
            self._get_tshark_process())
        parser = self._setup_tshark_output_parser()
        packets_captured = 0

        data = b""
        try:
            while True:
                try:
                    packet, data = self.eventloop.run_until_complete(
                        parser.get_packets_from_stream(tshark_process.stdout, data,
                                                       got_first_packet=packets_captured > 0))

                except EOFError:
                    self._log.debug("EOF reached (sync)")
                    self._eof_reached = True
                    break

                if packet:
                    packets_captured += 1
                    yield packet
                if packet_count and packets_captured >= packet_count:
                    break
        finally:
            if tshark_process in self._running_processes:
                self.eventloop.run_until_complete(
                    self._cleanup_subprocess(tshark_process))

    def apply_on_packets(self, callback, timeout=None, packet_count=None):
        """Runs through all packets and calls the given callback (a function) with each one as it is read.

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
                await self.close_async()

    async def _go_through_packets_from_fd(self, fd, packet_callback, packet_count=None):
        """A coroutine which goes through a stream and calls a given callback for each XML packet seen in it."""
        packets_captured = 0
        self._log.debug("Starting to go through packets")

        parser = self._setup_tshark_output_parser()
        data = b""

        while True:
            try:
                packet, data = await parser.get_packets_from_stream(fd, data,
                                                                    got_first_packet=packets_captured > 0)
            except EOFError:
                self._log.debug("EOF reached")
                self._eof_reached = True
                break

            if packet:
                packets_captured += 1
                try:
                    packet_callback(packet)
                except StopCapture:
                    self._log.debug("User-initiated capture stop in callback")
                    break

            if packet_count and packets_captured >= packet_count:
                break

    def _create_stderr_handling_task(self, stderr):
        self._stderr_handling_tasks.append(asyncio.ensure_future(self._handle_process_stderr_forever(stderr)))

    async def _handle_process_stderr_forever(self, stderr):
        while True:
            stderr_line = await stderr.readline()
            if not stderr_line:
                break
            stderr_line = stderr_line.decode().strip()
            self._last_error_line = stderr_line
            self._log.debug(stderr_line)

    def _get_tshark_path(self):
        return get_process_path(self.tshark_path)

    def _get_tshark_version(self):
        if self.__tshark_version is None:
            self.__tshark_version = get_tshark_version(self.tshark_path)
        return self.__tshark_version

    async def _get_tshark_process(self, packet_count=None, stdin=None):
        """Returns a new tshark process with previously-set parameters."""
        self._verify_capture_parameters()

        output_parameters = []
        if self.use_json or self._use_ek:
            if not tshark_supports_json(self._get_tshark_version()):
                raise TSharkVersionException(
                    "JSON only supported on Wireshark >= 2.2.0")

        if self.use_json:
            output_type = "json"
            if tshark_supports_duplicate_keys(self._get_tshark_version()):
                output_parameters.append("--no-duplicate-keys")
        elif self._use_ek:
            output_type = "ek"
        else:
            output_type = "psml" if self._only_summaries else "pdml"
        parameters = [self._get_tshark_path(), "-l", "-n", "-T", output_type] + \
            self.get_parameters(packet_count=packet_count) + output_parameters

        self._log.debug(
            "Creating TShark subprocess with parameters: " + " ".join(parameters))
        self._log.debug("Executable: %s", parameters[0])
        tshark_process = await asyncio.create_subprocess_exec(*parameters,
                                                              stdout=subprocess.PIPE,
                                                              stderr=subprocess.PIPE,
                                                              stdin=stdin)
        self._create_stderr_handling_task(tshark_process.stderr)
        self._created_new_process(parameters, tshark_process)
        return tshark_process

    def _created_new_process(self, parameters, process, process_name="TShark"):
        self._log.debug(
            process_name + f" subprocess (pid {process.pid}) created")
        if process.returncode is not None and process.returncode != 0:
            raise TSharkCrashException(
                f"{process_name} seems to have crashed. Try updating it. (command ran: '{' '.join(parameters)}')")
        self._running_processes.add(process)

    async def _cleanup_subprocess(self, process):
        """Kill the given process and properly closes any pipes connected to it."""
        self._log.debug(f"Cleanup Subprocess (pid {process.pid})")
        if process.returncode is None:
            try:
                process.kill()
                return await asyncio.wait_for(process.wait(), 1)
            except asyncTimeoutError:
                self._log.debug(
                    "Waiting for process to close failed, may have zombie process.")
            except ProcessLookupError:
                pass
            except OSError:
                if os.name != "nt":
                    raise
        elif process.returncode > 0:
            if process.returncode != 1 or self._eof_reached:
                raise TSharkCrashException(f"TShark (pid {process.pid}) seems to have crashed (retcode: {process.returncode}).\n"
                                           f"Last error line: {self._last_error_line}\n"
                                           "Try rerunning in debug mode [ capture_obj.set_debug() ] or try updating tshark.")

    def _setup_tshark_output_parser(self):
        if self.use_json:
            return tshark_json.TsharkJsonParser(self._get_tshark_version())
        if self._use_ek:
            ek_field_mapping.MAPPING.load_mapping(str(self._get_tshark_version()),
                                                  tshark_path=self.tshark_path)
            return tshark_ek.TsharkEkJsonParser()
        return tshark_xml.TsharkXmlParser(parse_summaries=self._only_summaries)

    def close(self):
        self.eventloop.run_until_complete(self.close_async())

    async def close_async(self):
        for process in self._running_processes.copy():
            await self._cleanup_subprocess(process)
        self._running_processes.clear()

        # Wait for all stderr handling to finish
        await asyncio.gather(*self._stderr_handling_tasks)

    def __del__(self):
        if self._running_processes:
            self.close()

    def __enter__(self): return self
    async def __aenter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()

    async def __aexit__(self, exc_type, exc_val,
                        exc_tb): await self.close_async()

    def get_parameters(self, packet_count=None):
        """Returns the special tshark parameters to be used according to the configuration of this class."""
        params = []
        if self._capture_filter:
            params += ["-f", self._capture_filter]
        if self._display_filter:
            params += [get_tshark_display_filter_flag(self._get_tshark_version(),),
                       self._display_filter]
        # Raw is only enabled when JSON is also enabled.
        if self.include_raw:
            params += ["-x"]
        if packet_count:
            params += ["-c", str(packet_count)]

        if self._custom_parameters:
            if isinstance(self._custom_parameters, list):
                params += self._custom_parameters
            elif isinstance(self._custom_parameters, dict):
                for key, val in self._custom_parameters.items():
                    params += [key, val]
            else:
                raise TypeError("Custom parameters type not supported.")

        if all(self.encryption):
            params += ["-o", "wlan.enable_decryption:TRUE", "-o", 'uat:80211_keys:"' + self.encryption[1] + '","' +
                                                                  self.encryption[0] + '"']
        if self._override_prefs:
            for preference_name, preference_value in self._override_prefs.items():
                if all(self.encryption) and preference_name in ("wlan.enable_decryption", "uat:80211_keys"):
                    continue  # skip if override preferences also given via --encryption options
                params += ["-o", f"{preference_name}:{preference_value}"]

        if self._output_file:
            params += ["-w", self._output_file]

        if self._decode_as:
            for criterion, decode_as_proto in self._decode_as.items():
                params += ["-d",
                           ",".join([criterion.strip(), decode_as_proto.strip()])]

        if self._disable_protocol:
            params += ["--disable-protocol", self._disable_protocol.strip()]

        return params

    def __iter__(self):
        if self.loaded:
            return iter(self._packets)
        else:
            return self._packets_from_tshark_sync()

    def __repr__(self):
        return f"<{self.__class__.__name__} ({len(self._packets)} packets)>"
