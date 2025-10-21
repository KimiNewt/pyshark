import pathlib

import pytest

import pyshark


@pytest.fixture
def data_directory():
    return pathlib.Path(__file__).parent.joinpath('data')


@pytest.fixture
def example_pcap_path(data_directory):
    return data_directory.joinpath('capture_test.pcapng')


@pytest.fixture
def lazy_simple_capture(example_pcap_path):
    with pyshark.FileCapture(example_pcap_path, debug=True) as pcap:
        yield pcap


@pytest.fixture
def simple_capture(lazy_simple_capture):
    """A capture already full of packets"""
    lazy_simple_capture.load_packets()
    return lazy_simple_capture


@pytest.fixture
def simple_summary_capture(example_pcap_path):
    with pyshark.FileCapture(example_pcap_path, debug=True, only_summaries=True) as pcap:
        yield pcap


@pytest.fixture(params=[True, False])
def simple_xml_and_json_capture(request, example_pcap_path):
    with pyshark.FileCapture(example_pcap_path, debug=True, use_json=request.param) as pcap:
        yield pcap
