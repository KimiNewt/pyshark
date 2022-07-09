import pathlib
from unittest import mock

import pytest

from pyshark import ek_field_mapping


@pytest.fixture(autouse=True)
def fake_cache(tmp_path):
    with mock.patch.object(ek_field_mapping, "cache") as fake_cache_module:
        # Direct to the data directory which has the mapping for IP.
        fake_cache_module.get_cache_dir.return_value = pathlib.Path(__file__).parent.joinpath("data")
        yield fake_cache_module.get_cache_dir


@pytest.fixture
def mapping():
    ek_field_mapping.MAPPING.load_mapping("foo")
    yield ek_field_mapping.MAPPING
    ek_field_mapping.MAPPING.clear()


@pytest.mark.parametrize(["field_name", "expected_type"], [
    ("ip_ip_hdr_len", int),
    ("ip_ip_src_rt", str),
    ("ip_ip_geoip_lat", float),
    ("ip_ip_tos_reliability", str),
    ("ip_ip_reassembled_data", bytes),
    ("missing_field", str),
])
def test_can_find_field_type_in_mapping(mapping, field_name, expected_type):
    assert mapping.get_field_type("ip", field_name) == expected_type


@pytest.mark.parametrize(["field_name", "str_value", "casted_value"], [
    ("ip_ip_hdr_len", "20", 20),
    ("ip_ip_src_rt", "1.1.1.1", "1.1.1.1"),
    ("ip_ip_geoip_lat", "15.5", 15.5),
    ("ip_ip_tos_reliability", "foo", "foo"),
    ("ip_ip_checksum", "0x3006", 0x3006),
    ("ip_ip_checksum", ["0x3006", "0x5"], [0x3006, 0x5]),
    ("ip_ip_reassembled_data", "ff:e0", b"\xff\xe0"),
])
def test_casts_field_value_to_correct_value(mapping, field_name, str_value, casted_value):
    assert mapping.cast_field_value("ip", field_name, str_value) == casted_value


def test_doesnt_cast_non_str(mapping):
    assert mapping.cast_field_value("ip", "ip_ip_hdr_len", True) is True


