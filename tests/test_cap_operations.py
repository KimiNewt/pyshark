import time
from asyncio import TimeoutError
from multiprocessing import Process
from multiprocessing import Queue
from multiprocessing.queues import Empty
from unittest import mock

import pytest

from pyshark.packet.packet_summary import PacketSummary


def test_packet_callback_called_for_each_packet(lazy_simple_capture):
    # Test cap has 24 packets
    mock_callback = mock.Mock()
    lazy_simple_capture.apply_on_packets(mock_callback)
    assert mock_callback.call_count == 24


def test_async_packet_callback_called_for_each_packet(lazy_simple_capture):
    # Test cap has 24 packets
    mock_callback = mock.AsyncMock()
    lazy_simple_capture.apply_on_packets(mock_callback)
    assert mock_callback.call_count == 24
    mock_callback.assert_awaited()


def test_apply_on_packet_stops_on_timeout(lazy_simple_capture):
    def wait(pkt):
        time.sleep(5)
    with pytest.raises(TimeoutError):
        lazy_simple_capture.apply_on_packets(wait, timeout=1)


def test_lazy_loading_of_packets_on_getitem(lazy_simple_capture):
    # Seventh packet is ICMP
    assert 'ICMP' in lazy_simple_capture[6]


def test_lazy_loading_of_packet_does_not_recreate_packets(lazy_simple_capture):
    # Seventh packet is ICMP
    icmp_packet_id = id(lazy_simple_capture[6])
    # load some more
    lazy_simple_capture[8]
    assert icmp_packet_id == id(lazy_simple_capture[6])


def test_filling_cap_in_increments(lazy_simple_capture):
    lazy_simple_capture.load_packets(1)
    assert len(lazy_simple_capture) == 1
    lazy_simple_capture.load_packets(2)
    assert len(lazy_simple_capture) == 3


def test_getting_packet_summary(simple_summary_capture):
    assert isinstance(simple_summary_capture[0], PacketSummary)

    # Since we cannot check the exact fields since they're dependent on wireshark configuration,
    # we'll at least make sure some data is in.
    assert simple_summary_capture[0]._fields


def _iterate_capture_object(cap_obj, q):
    for _ in cap_obj:
        pass
    q.put(True)


def test_iterate_empty_psml_capture(simple_summary_capture):
    simple_summary_capture.display_filter = "frame.len == 1"
    q = Queue()
    p = Process(target=_iterate_capture_object,
                args=(simple_summary_capture, q))
    p.start()
    p.join(2)
    try:
        no_hang = q.get_nowait()
    except Empty:
        no_hang = False
    if p.is_alive():
        p.terminate()
    assert no_hang  # False here
