import binascii
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
def test_can_access_layer(icmp_packet, access_func):
    """Tests that layer access in various ways works the same way."""
    assert access_func(icmp_packet).layer_name.upper() == 'ICMP'
    assert binascii.unhexlify(access_func(icmp_packet).data) == b'abcdefghijklmnopqrstuvwabcdefghi'


def test_packet_contains_layer(icmp_packet):
    assert 'ICMP' in icmp_packet


def test_raw_mode(icmp_packet):
    original = icmp_packet.ip.src
    raw = icmp_packet.ip.src.raw_value
    icmp_packet.ip.raw_mode = True
    assert icmp_packet.ip.src != original
    assert icmp_packet.ip.src == raw


def test_frame_info_access(icmp_packet):
    actual = icmp_packet.frame_info.protocols
    expected = set(['eth:ip:icmp:data', 'eth:ethertype:ip:icmp:data'])
    assert actual in expected
    assert icmp_packet.frame_info.number == '8'
