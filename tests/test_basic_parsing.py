def test_count_packets(simple_xml_and_json_capture):
    """Test to make sure the right number of packets are read from a known
       capture"""
    packet_count = sum(1 for _ in simple_xml_and_json_capture)
    assert packet_count == 24


def test_sum_lengths(simple_xml_and_json_capture):
    """Test to make sure that the right packet length is being read from
       tshark's output by comparing the aggregate length of all packets
       to a known value"""
    total_length = sum(int(packet.length) for packet in simple_xml_and_json_capture)
    assert total_length == 2178


def test_layers(simple_xml_and_json_capture):
    """Test to make sure the correct protocols are reported for known
       packets"""
    packet_indexes = (0, 5, 6, 13, 14, 17, 23)
    test_values = [simple_xml_and_json_capture[i].highest_layer for i in packet_indexes]
    known_values = ['DNS', 'DNS', 'ICMP', 'ICMP', 'TCP', 'HTTP', 'TCP']
    assert test_values == known_values


def test_ethernet(simple_xml_and_json_capture):
    """Test to make sure Ethernet fields are being read properly by comparing
       packet dissection results to known values"""
    packet = simple_xml_and_json_capture[0]
    test_values = packet.eth.src, packet.eth.dst
    known_values = ('00:00:bb:10:20:10', '00:00:bb:02:04:01')
    assert test_values == known_values


def test_icmp(simple_xml_and_json_capture):
    """Test to make sure ICMP fields are being read properly by comparing
       packet dissection results to known values"""
    packet = simple_xml_and_json_capture[11]
    # The value returned by tshark is locale-dependent.
    # Depending on the locale, a comma can be used instead of a dot
    # as decimal separator.
    resptime = packet.icmp.resptime.replace(',', '.')
    assert resptime == '1.667'
