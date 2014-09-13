import os
import pytest

import pyshark

@pytest.fixture
def caps_directory():
    return os.path.join(os.path.dirname(__file__), 'caps')

@pytest.fixture
def simple_capture(request, caps_directory):
    cap_path = os.path.join(caps_directory, 'capture_test.pcapng')
    cap = pyshark.FileCapture(cap_path)
    cap.load_packets()

    def finalizer():
        cap.close()
        cap.eventloop.stop()
    request.addfinalizer(finalizer)
    return cap