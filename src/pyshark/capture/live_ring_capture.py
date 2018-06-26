from pyshark import LiveCapture

class LiveRingCapture(LiveCapture):
    """
    Represents a live ringbuffer capture on a network interface.
    """

    def __init__(self, ring_file_size=1024, num_ring_files=1, ring_file_name='/tmp/pyshark.pcap', interface=None,
                 bpf_filter=None, display_filter=None, only_summaries=False, decryption_key=None,
                 encryption_type='wpa-pwk', decode_as=None, disable_protocol=None,
                 tshark_path=None, override_prefs=None, include_raw=False):
        """
        Creates a new live capturer on a given interface. Does not start the actual capture itself.
        :param ring_file_size: Size of the ring file in kB, default is 1024
        :param num_ring_files: Number of ring files to keep, default is 1
        :param ring_file_name: Name of the ring file, default is /tmp/pyshark.pcap
        :param interface: Name of the interface to sniff on or a list of names (str). If not given, runs on all interfaces.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD', or
        'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.
        """
        super(LiveRingCapture, self).__init__(interface, bpf_filter=bpf_filter, display_filter=display_filter, only_summaries=only_summaries,
                                              decryption_key=decryption_key, encryption_type=encryption_type,
                                              tshark_path=tshark_path, decode_as=decode_as, disable_protocol=disable_protocol,
                                              override_prefs=override_prefs, include_raw=include_raw)

        self.ring_file_size = ring_file_size
        self.num_ring_files = num_ring_files
        self.ring_file_name = ring_file_name

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(LiveRingCapture, self).get_parameters(packet_count=packet_count)
        params += ['-b', 'filesize:' + str(self.ring_file_size), '-b', 'files:' + str(self.num_ring_files), '-w', self.ring_file_name, '-P']
        return params
