import subprocess
from unittest import mock

import pytest

from pyshark.tshark import tshark


LINUX_INTERFACES_OUTPUT = b"""
10. br-15
11. any
12. lo (Loopback)
13. br-cc"""

WINDOWS_INTERFACES_OUTPUT = rb"""
1. \Device\NPF_{1} (foo)
2. \Device\NPF_{2} (bar)"""


@pytest.fixture
def mock_check_output():
    with mock.patch.object(subprocess, "check_output") as mock_check_output:
        yield mock_check_output


@pytest.mark.parametrize(["tshark_output", "expected_interface_names"],
                         [
                             (b"foo", []),
                             (b"1. foo\n2. bar\n3. baz", ["foo", "bar", "baz"]),
                             (b"1. foo\n2. bar (derp)\n3. baz", ["foo", "bar", "baz", "derp"]),
                             (LINUX_INTERFACES_OUTPUT, ["br-15", "any", "lo", "Loopback", "br-cc"]),
                             (WINDOWS_INTERFACES_OUTPUT,
                              [r"\Device\NPF_{1}", r"\Device\NPF_{2}", "foo", "bar"])
                         ]
                         )
def test_can_get_all_interface_names_and_aliases(mock_check_output, tshark_output, expected_interface_names):
    mock_check_output.return_value = tshark_output
    assert set(tshark.get_all_tshark_interfaces_names()) == set(expected_interface_names)
