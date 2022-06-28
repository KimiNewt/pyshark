import pytest

from pyshark import ek_field_mapping
from pyshark.tshark import tshark
from pyshark.tshark.output_parser import tshark_ek


@pytest.fixture
def parsed_packet(data_directory):
    ek_field_mapping.MAPPING.load_mapping(str(tshark.get_tshark_version()))
    return tshark_ek.packet_from_ek_packet(data_directory.joinpath("packet_ek.json").read_bytes())


def test_can_access_simple_field(parsed_packet):
    assert parsed_packet.tcp.checksum.value == 0x0000b71f


def test_can_access_subfield(parsed_packet):
    assert parsed_packet.tcp.flags.ack is True


def test_can_access_subfield_by_dot_notations(parsed_packet):
    assert parsed_packet.tcp.get_field("flags.ack") is True


def test_can_parse_duplicate_fields(parsed_packet):
    assert parsed_packet.tcp.options.timestamp.tsecr == 360352231
    assert parsed_packet.tcp.options.nop == ["01", "01"]


def test_gets_layer_field_names(parsed_packet):
    assert set(parsed_packet.tcp.field_names) == {"checksum",
                                                  "nxtseq",
                                                  "flags",
                                                  "dstport",
                                                  "ack",
                                                  "stream",
                                                  "port",
                                                  "seq",
                                                  "srcport",
                                                  "urgent",
                                                  "option",
                                                  "analysis",
                                                  "options",
                                                  "window",
                                                  "payload",
                                                  "len",
                                                  "time",
                                                  "hdr"}


def test_gets_field_subfield_names(parsed_packet):
    assert set(parsed_packet.tcp.options.timestamp.subfields) == {"tsecr", "tsval"}
