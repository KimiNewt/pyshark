from multiprocessing import TimeoutError
import subprocess
import threading
import sys
from pyshark.tshark.tshark import get_tshark_path
from pyshark.tshark.tshark_xml import packets_from_file, packets_from_xml


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
        p = subprocess.Popen([get_tshark_path(), '-T', 'pdml'] + self.get_parameters(packet_count=packet_count),
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
        sniff_thread = threading.Thread(target=self._sniff_in_thread, args=(p,))
        try:
            sniff_thread.start()
            if timeout is None:
                timeout = sys.maxint
            sniff_thread.join(timeout=timeout)
        except KeyboardInterrupt:
            print 'Interrupted, stopping..'
        except TimeoutError:
            pass

        self.packets += packets_from_xml(p.stdout.read())
        if sniff_thread.is_alive() and p.poll():
            p.terminate()
        sniff_thread.join()

    def _sniff_in_thread(self, proc):
        proc.wait()

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
            params += ['-c', packet_count]
        return params