import pytest

@pytest.fixture
def icmp_packet(simple_capture):
    return simple_capture[7]


@pytest.mark.parametrize('access_func', [
    lambda pkt: pkt[-1],
    lambda pkt: pkt['icmp'],
    lambda pkt: pkt['ICMP'],
    lambda pkt: pkt.icmp,
])
def test_layer_access(icmp_packet, access_func):
    """
    Tests that layer access in various ways works the same way.
    """
    assert access_func(icmp_packet).layer_name.upper() == 'ICMP'
    assert access_func(icmp_packet).data == 'abcdefghijklmnopqrstuvwabcdefghi'.encode('hex')


def test_packet_contains_layer(icmp_packet):
    assert 'ICMP' in icmp_packet


def test_raw_mode(icmp_packet):
    original = icmp_packet.ip.src
    raw = icmp_packet.ip.get_raw_value('src')
    icmp_packet.ip.raw_mode = True
    assert icmp_packet.ip.src != original
    assert icmp_packet.ip.src == raw