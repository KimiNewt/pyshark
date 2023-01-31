from pyshark.capture.capture import Capture


def test_capture_gets_decoding_parameters():
    c = Capture(decode_as={'tcp.port==8888': 'http'})
    params = c.get_parameters()
    decode_index = params.index('-d')
    assert params[decode_index + 1] == 'tcp.port==8888,http'


def test_capture_gets_multiple_decoding_parameters():
    c = Capture(decode_as={'tcp.port==8888': 'http', 'tcp.port==6666': 'dns'})
    params = c.get_parameters()
    decode_index = params.index('-d')
    possible_results = ['tcp.port==8888,http', 'tcp.port==6666,dns']
    assert params[decode_index + 1] in possible_results
    possible_results.remove(params[decode_index + 1])
    decode_index = params.index('-d', decode_index + 1)
    assert params[decode_index + 1] == possible_results[0]


def test_capture_gets_override_perfs():
    c = Capture(override_prefs={'esp.enable_null_encryption_decode_heuristic': 'TRUE'})
    params = c.get_parameters()
    override_index = params.index('-o')
    override_actual_value = params[override_index +1]
    assert override_actual_value == 'esp.enable_null_encryption_decode_heuristic:TRUE'


def test_capture_gets_multiple_override_perfs():
    c = Capture(override_prefs={'esp.enable_null_encryption_decode_heuristic': 'TRUE',
                                'tcp.ls_payload_display_len':'80'})
    params = c.get_parameters()
    expected_results = ('esp.enable_null_encryption_decode_heuristic:TRUE',
                        'tcp.ls_payload_display_len:80')
    start_idx = 0
    for count in range(len(expected_results)):
        override_index = params.index('-o', start_idx)
        override_actual_value = params[override_index +1]
        assert override_actual_value in expected_results
        # increment index
        start_idx = override_index + 1


def test_capture_gets_encryption_and_override_perfs():
    temp_c = Capture()
    for valid_encryption_type in temp_c.SUPPORTED_ENCRYPTION_STANDARDS:
        c = Capture(decryption_key='helloworld',
                    encryption_type=valid_encryption_type,
                    override_prefs={'esp.enable_null_encryption_decode_heuristic': 'TRUE',
                                    'wlan.enable_decryption': 'TRUE',
                                    'uat:80211_keys': f'"{valid_encryption_type}","helloworld"'})
        params = c.get_parameters()
        expected_results = ('esp.enable_null_encryption_decode_heuristic:TRUE',
                            'wlan.enable_decryption:TRUE',
                            f'uat:80211_keys:"{valid_encryption_type}","helloworld"')
        start_idx = 0
        actual_parameter_options = []
        while True:
            try:
                override_index = params.index('-o', start_idx)
            except ValueError:
                # no more '-o' options
                break
            override_actual_value = params[override_index +1]
            actual_parameter_options.append(override_actual_value)
            assert override_actual_value in expected_results
            # increment index
            start_idx = override_index + 1
        assert set(actual_parameter_options) == set(expected_results)
        assert len(actual_parameter_options) == len(expected_results)

