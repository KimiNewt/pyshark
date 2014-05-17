from pyshark import LiveCapture


class RemoteCapture(LiveCapture):
    """
    A capture which is performed on a remote machine which has an rpcapd service running.
    """

    def __init__(self, remote_host, remote_interface, remote_port=2002, bpf_filter=None):
        """
        Creates a new remote capture which will connect to a remote machine which is running rpcapd. Use the sniff() method
        to get packets.
        Note: The remote machine should have rpcapd running in null authentication mode (-n). Be warned that the traffic
        is unencrypted!

        :param remote_host: The remote host to capture on (IP or hostname). Should be running rpcapd.
        :param remote_interface: The remote interface on the remote machine to capture on. Note that on windows it is
        not the device display name but the true interface name (i.e. \\Device\\NPF_..).
        :param remote_port: The remote port the rpcapd service is listening on
        :param bpf_filter: A BPF (tcpdump) filter to apply on the cap before reading.
        """
        interface = 'rpcap://%s:%d/%s' % (remote_host, remote_port, remote_interface)
        super(RemoteCapture, self).__init__(interface, bpf_filter=bpf_filter)