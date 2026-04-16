import binascii
import pytest
import pyshark


@pytest.fixture
def inmem_capture():
    return pyshark.InMemCapture()


def arp_packet(last_byte='f'):
    """
    Returns an ARP packet from aa:bb:cc:dd:ee:fX
    """
    p = f"ffffffffffffaabbccddeef{last_byte}0806000108000604000104a151c32ad10a0000020000000000000a000001"
    return binascii.unhexlify(p)


def test_can_read_binary_packet(inmem_capture):
    pkt = inmem_capture.parse_packet(arp_packet('f'))
    inmem_capture.close()
    assert pkt.eth.src == 'aa:bb:cc:dd:ee:ff'


def test_can_read_multiple_binary_packet(inmem_capture):
    pkts = inmem_capture.feed_packets([arp_packet('1'), arp_packet('2'), arp_packet('3')])
    assert len(pkts) == 3

    for i, pkt in enumerate(pkts):
        assert pkt.eth.src == 'aa:bb:cc:dd:ee:f' + str(i + 1)

def test_fed_packets_are_added_to_the_list(inmem_capture):
    inmem_capture.feed_packets([arp_packet()])
    assert len(inmem_capture) == 1

    inmem_capture.feed_packets([arp_packet(), arp_packet()])
    assert len(inmem_capture) == 3
