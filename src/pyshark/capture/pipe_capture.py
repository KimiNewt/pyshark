import trollius as asyncio
from trollius import From, Return

from pyshark.capture.capture import Capture


class PipeCapture(Capture):
    def __init__(self, pipe, display_filter=None, only_summaries=False,
                 decryption_key=None, encryption_type='wpa-pwk', decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None, use_json=False, include_raw=False,
                 eventloop=None, custom_parameters=None):
        """
        Receives a file-like and reads the packets from there (pcap format).

        :param bpf_filter: BPF filter to use on packets.
        :param display_filter: Display (wireshark) filter to use.
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
        :param custom_parameters: A dict of custom parameters to pass to tshark, i.e. {"--param": "value"}
        """
        super(PipeCapture, self).__init__(display_filter=display_filter,
                                          only_summaries=only_summaries,
                                          decryption_key=decryption_key,
                                          encryption_type=encryption_type,
                                          decode_as=decode_as, disable_protocol=disable_protocol,
                                          tshark_path=tshark_path, override_prefs=override_prefs,
                                          use_json=use_json, include_raw=include_raw, eventloop=eventloop,
                                          custom_parameters=custom_parameters)
        self._pipe = pipe

    def get_parameters(self, packet_count=None):
        """
        Returns the special tshark parameters to be used according to the configuration of this class.
        """
        params = super(PipeCapture, self).get_parameters(packet_count=packet_count)
        params += ['-r', '-']
        return params

    @asyncio.coroutine
    def _get_tshark_process(self, packet_count=None):
        proc = yield From(super(PipeCapture, self)._get_tshark_process(packet_count=packet_count,
                                                                       stdin=self._pipe))
        raise Return(proc)

    def close(self):
        # Close pipe
        self._pipe.close()
        super(PipeCapture, self).close()
