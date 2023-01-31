from pyshark import LiveCapture


class RemoteCapture(LiveCapture):
    """A capture which is performed on a remote machine which has an rpcapd service running."""

    def __init__(
        self,
        remote_host,
        remote_interface,
        *args,
        remote_port=2002,
        bpf_filter=None,
        only_summaries=False,
        decryption_key=None,
        encryption_type="wpa-pwk",
        decode_as=None,
        disable_protocol=None,
        tshark_path=None,
        override_prefs=None,
        eventloop=None,
        debug=False,
        **kwargs
    ):
        """
        Creates a new remote capture which will connect to a remote machine which is running rpcapd. Use the sniff()
        method to get packets.
        Note: The remote machine should have rpcapd running in null authentication mode (-n). Be warned that the traffic
        is unencrypted!

        Note:
            *args and **kwargs are passed to LiveCature's __init__ method.


        :param remote_host: The remote host to capture on (IP or hostname). Should be running rpcapd.
        :param remote_interface: The remote interface on the remote machine to capture on. Note that on windows it is
        not the device display name but the true interface name (i.e. \\Device\\NPF_..).
        :param remote_port: The remote port the rpcapd service is listening on
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        :param only_summaries: Only produce packet summaries, much faster but includes very little information
        :param decryption_key: Key used to encrypt and decrypt captured traffic.
        :param encryption_type: Standard of encryption used in captured traffic (must be either 'WEP', 'WPA-PWD',
        or 'WPA-PWK'. Defaults to WPA-PWK).
        :param decode_as: A dictionary of {decode_criterion_string: decode_as_protocol} that are used to tell tshark
        to decode protocols in situations it wouldn't usually, for instance {'tcp.port==8888': 'http'} would make
        it attempt to decode any port 8888 traffic as HTTP. See tshark documentation for details.
        :param tshark_path: Path of the tshark binary
        :param override_prefs: A dictionary of tshark preferences to override, {PREFERENCE_NAME: PREFERENCE_VALUE, ...}.
        :param disable_protocol: Tells tshark to remove a dissector for a specifc protocol.
        """
        interface =  f'rpcap://{remote_host}:{remote_port}/{remote_interface}'
        super(RemoteCapture, self).__init__(
            interface,
            *args,
            bpf_filter=bpf_filter,
            only_summaries=only_summaries,
            decryption_key=decryption_key,
            encryption_type=encryption_type,
            tshark_path=tshark_path,
            decode_as=decode_as,
            disable_protocol=disable_protocol,
            override_prefs=override_prefs,
            eventloop=eventloop,
            debug=debug,
            **kwargs
        )
