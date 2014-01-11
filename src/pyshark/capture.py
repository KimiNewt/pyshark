from multiprocessing import TimeoutError
import subprocess
import threading
import sys
from pyshark.tshark.tshark import get_tshark_path
from pyshark.tshark.tshark_xml import packets_from_file, packets_from_xml, packet_from_xml_packet
from pyshark.utils import StoppableThread


class Capture(object):
    """
    Base class for packet captures.
    """

    def __init__(self):
        self.packets = []
        self.current_packet = 0

    def __getitem__(self, item):
        return self.packets[item]

    def next(self):
        if self.current_packet >= len(self.packets):
            raise StopIteration()
        cur_packet = self.packets[self.current_packet]
        self.current_packet += 1
        return cur_packet

    def clear(self):
        """
        Empties the capture of any saved packets.
        """
        self.packets = []
        self.current_packet = 0

    def __iter__(self):
        for packet in self.packets:
            yield packet

    def __repr__(self):
        return '<%s (%d packets)>' %(self.__class__.__name__, len(self.packets))


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

        self.xml_data, self.packets = packets_from_file(self.input_file)

    def close(self):
        if not self.input_file.closed:
            self.input_file.close()

    def __repr__(self):
        return '<%s %s (%d packets)>' %(self.__class__.__name__, self.filename, len(self.packets))

    @property
    def filename(self):
        """
        Returns the filename of the capture file represented by this object.
        """
        return self.input_file.name


class LiveCapture(Capture):
    """
    Represents a live capture on a network interface.
    """

    def __init__(self, interface=None, bpf_filter=None, display_filter=None):
        """
        Creates a new live capturer on a given interface. Does not start the actual capture itself.

        :param interface: Name of the interface to sniff on. If not given, takes the first available.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        """
        super(LiveCapture, self).__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.display_filter = display_filter

    def sniff(self, packet_count=None, timeout=None):
        """
        Captures from the set interface, until the given amount of packets is captured or the timeout is reached.
        When using interactively, can be stopped by a Keyboard Interrupt.
        All packets are added to the packet list. Can be called multiple times.

        :param packet_count: an amount of packets to capture, then stop.
        :param timeout: stop capturing after this given amount of time.
        """
        sniff_thread = StoppableThread(target=self._sniff_in_thread, args=(packet_count,))
        try:
            sniff_thread.start()
            if timeout is None:
                timeout = sys.maxint
            sniff_thread.join(timeout=timeout)
            if sniff_thread.is_alive():
                # Thread still alive after join, must have timed out.
                sniff_thread.raise_exc(StopIteration)
        except KeyboardInterrupt:
            print 'Interrupted, stopping..'
            sniff_thread.raise_exc(StopIteration)

        sniff_thread.join()

    def _sniff_in_thread(self, packet_count=None):
        """
        Sniff until stopped and add all packets to the packet list.

        :param proc: tshark process to use to sniff.
        """
        proc = self._get_tshark_process(packet_count)
        try:
            for packet in self.sniff_continuously(packet_count=packet_count,
                                                  existing_tshark=proc):
                self.packets += [packet]
        except StopIteration:
            try:
                if proc.poll() is not None:
                    # Process has not terminated yet
                    proc.terminate()
            except WindowsError:
                # If process already terminated somehow.
                pass

    def _get_tshark_process(self, packet_count=None):
        """
        Gets a new tshark process with the previously-set paramaters.
        """
        return subprocess.Popen([get_tshark_path(), '-T', 'pdml'] + self.get_parameters(packet_count=packet_count),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def sniff_continuously(self, packet_count=None, existing_tshark=None):
        """
        Captures from the set interface, returning a generator which returns packets continuously.

        Can be used as follows:
        for packet in capture.sniff_continuously();
            print 'Woo, another packet:', packet

        :param packet_count: an amount of packets to capture, then stop.
        :param existing_tshark: an existing tshark subprocess (for internal use).
        """
        if existing_tshark:
            proc = existing_tshark
        else:
            proc = self._get_tshark_process(packet_count=packet_count)
        data = ''
        packets_captured = 0

        while True:
            # Read data until we get a packet, and yield it.
            data += proc.stdout.read(100)
            packet, data = self.extract_packet_from_data(data)

            if packet:
                packets_captured += 1
                yield packet_from_xml_packet(packet)

            if packet_count and packets_captured >= packet_count:
                break

        try:
            if proc.poll() is not None:
                proc.terminate()
        except WindowsError:
            # On windows
            pass

    def extract_packet_from_data(self, data):
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

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = []
        if self.interface:
            params += ['-i', self.interface]
        if self.bpf_filter:
            params += ['-f', self.bpf_filter]
        if self.display_filter:
            params += ['-Y', self.display_filter]
        if packet_count:
            params += ['-c', str(packet_count)]
        return params