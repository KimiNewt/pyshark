import pytest

from pyshark.tshark.output_parser import tshark_json


@pytest.fixture
def parsed_packet(data_directory):
    return tshark_json.packet_from_json_packet(data_directory.joinpath("packet.json").read_bytes())


def test_can_access_simple_field(parsed_packet):
    assert parsed_packet.tcp.checksum == "0x0000b71f"


def test_can_access_subfield(parsed_packet):
    assert parsed_packet.tcp.flags_tree.ack == "1"


def test_can_duplicate_fields(parsed_packet):
    assert parsed_packet.tcp.options_tree.nop == ["01", "01"]
    assert parsed_packet.tcp.options_tree.timestamp_tree.option_kind == "8"


