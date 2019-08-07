import os

import pytest

import pyshark


CAPS_DIRECTORY = os.path.join(os.path.dirname(__file__), 'caps')


def make_test_capture(request, **params):
    cap_path = os.path.join(CAPS_DIRECTORY, 'capture_test.pcapng')
    cap = pyshark.FileCapture(cap_path, **params)
    cap.set_debug()

    def finalizer():
        cap.close()

    request.addfinalizer(finalizer)
    return cap


@pytest.fixture
def lazy_simple_capture(request):
    """
    Does not fill the cap with packets.
    """
    return make_test_capture(request)


@pytest.fixture
def simple_capture(lazy_simple_capture):
    """
    A capture already full of packets
    """
    lazy_simple_capture.load_packets()
    return lazy_simple_capture


@pytest.fixture
def simple_summary_capture(request):
    """
    A capture already full of packets
    """
    return make_test_capture(request, only_summaries=True)


@pytest.fixture(params=[True, False])
def simple_xml_and_json_capture(request):
    return make_test_capture(request, use_json=request.param)
