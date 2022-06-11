import pytest

from pyshark.tshark import tshark_ek
from pyshark.tshark import tshark_xml


@pytest.fixture
def parsed_packet(data_directory):
    return tshark_ek.packet_from_ek_packet(data_directory.joinpath("packet_ek.json").read_bytes())


def test_can_access_simple_field(parsed_packet):
    assert parsed_packet.tcp.checksum.value == "0x0000b71f"


def test_can_access_subfield(parsed_packet):
    assert parsed_packet.tcp.flags.ack is True


def test_can_duplicate_fields(parsed_packet):
    all_tcp_opts = parsed_packet.tcp.option_kind.all_fields
    assert {opt.get_default_value() for opt in all_tcp_opts} == {"1", "1", "8"}


