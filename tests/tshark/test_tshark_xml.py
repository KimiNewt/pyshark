import pytest

from pyshark.tshark.output_parser import tshark_xml


@pytest.fixture
def parsed_packet(data_directory):
    return tshark_xml.packet_from_xml_packet(data_directory.joinpath("packet.xml").read_bytes())


def test_can_access_simple_field(parsed_packet):
    assert parsed_packet.tcp.checksum == "0x0000b71f"


def test_can_access_field_showname(parsed_packet):
    assert parsed_packet.tcp.checksum.showname == "Checksum: 0xb71f [correct]"


def test_can_access_raw_field(parsed_packet):
    assert parsed_packet.tcp.checksum.raw_value == "b71f"


def test_can_access_subfield(parsed_packet):
    assert parsed_packet.tcp.flags_ack == "1"


def test_can_duplicate_fields(parsed_packet):
    all_tcp_opts = parsed_packet.tcp.option_kind.all_fields
    assert {opt.get_default_value() for opt in all_tcp_opts} == {"1", "1", "8"}


