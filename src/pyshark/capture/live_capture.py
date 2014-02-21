import sys
import subprocess

from pyshark.capture.capture import Capture
from pyshark.tshark.tshark import get_tshark_path
from pyshark.utils import StoppableThread


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
        super(LiveCapture, self).__init__(bpf_filter=bpf_filter, display_filter=display_filter)
        self.interface = interface


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
                self._packets += [packet]
        except StopIteration:
            try:
                if proc.poll() is not None:
                    # Process has not terminated yet
                    proc.terminate()
            except WindowsError:
                # If process already terminated somehow.
                pass

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

        for packet in self._packets_from_fd(proc.stdout, packet_count=packet_count):
            yield packet

        try:
            if proc.poll() is not None:
                proc.terminate()
        except WindowsError:
            # On windows
            pass

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(LiveCapture, self).get_parameters(packet_count=packet_count)
        if self.interface:
            params += ['-i', self.interface]
        return params