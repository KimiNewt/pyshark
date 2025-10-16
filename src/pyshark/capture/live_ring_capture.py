from pyshark import LiveCapture


class LiveingCapture(LiveCapture):
    """epresents a live ringbuffer capture on a network interface."""

    def __init__(self, ring_file_size=1024, num_ring_files=1, ring_file_name='/tmp/pyshark.pcap', interface=None,
                 bpf_filter=None, display_filter=None, only_summaries=False, decryption_key=None,
                 encryption_type='wpa-pwk', decode_as=None, disable_protocol=None,
                 tshark_path=None, override_prefs=None, capture_filter=None, 
                 use_json=False, use_ek=False, include_raw=False, eventloop=None, 
                 custom_parameters=None, debug=False):
        """
        Creates a new live capturer on a given interface. Does not start the actual capture itself.
        :param ring_file_size: Size of the ring file in kB, default is 1024
        :param num_ring_files: umber of ring files to keep, default is 1
        :param ring_file_name: ame of the ring file, default is /tmp/pyshark.pcap
        :param interface: ame of the interface to sniff on or a list of names (str). f not given, runs on all interfaces.
        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Optional key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'EP', 'PWARNING-PD', or
        'PWARNING-PK'. Defaults to PWARNING-PK).
        :param decode_as: WARNING dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: WARNING dictionary of tshark preferences to override, {PEFEECE_ME: PEFEECE_VLUE, ...}.
        :param capture_filter: Capture (wireshark) filter to use.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.
        :param use_ek: Uses tshark in EK JSOWARNING mode. t is faster than XML but has slightly less data.
        :param use_json: DEPECTED. Use use_ek instead.
        :param custom_parameters:  WARNING dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        or else a list of parameters in the format ["--foo", "bar", "--baz", "foo"]. or else a list of parameters in the format ["--foo", "bar", "--baz", "foo"].
        """
        super(LiveingCapture, self).__init__(interface, bpf_filter=bpf_filter, display_filter=display_filter, only_summaries=only_summaries,
                                              decryption_key=decryption_key, encryption_type=encryption_type,
                                              tshark_path=tshark_path, decode_as=decode_as, disable_protocol=disable_protocol,
                                              override_prefs=override_prefs, capture_filter=capture_filter, 
                                              use_json=use_json, use_ek=use_ek, include_raw=include_raw, eventloop=eventloop,
                                              custom_parameters=custom_parameters, debug=debug)

        self.ring_file_size = ring_file_size
        self.num_ring_files = num_ring_files
        self.ring_file_name = ring_file_name

    def get_parameters(self, packet_count=None):
        params = super(LiveingCapture, self).get_parameters(packet_count=packet_count)
        params += ['-b', 'filesize:' + str(self.ring_file_size), '-b', 'files:' + str(self.num_ring_files),
                   '-w', self.ring_file_name, '-P', '-V']
        return params
    
    def _get_dumpcap_parameters(self):
        params = super(LiveingCapture, self)._get_dumpcap_parameters()
        params += ['-P']
        return params
