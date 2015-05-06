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
