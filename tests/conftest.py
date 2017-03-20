import os
import logbook
import pytest

import pyshark

@pytest.fixture
def caps_directory():
    return os.path.join(os.path.dirname(__file__), 'caps')

@pytest.fixture
def lazy_simple_capture(request, caps_directory):
    """
    Does not fill the cap with packets.
    """
    cap_path = os.path.join(caps_directory, 'capture_test.pcapng')
    cap = pyshark.FileCapture(cap_path)
    cap.set_debug()

    def finalizer():
        cap.close()
        cap.eventloop.stop()
    request.addfinalizer(finalizer)
    return cap

@pytest.fixture
def simple_capture(lazy_simple_capture):
    """
    A capture already full of packets
    """
    lazy_simple_capture.load_packets()
    return lazy_simple_capture