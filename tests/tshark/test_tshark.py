import subprocess
from unittest import mock
from packaging import version

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


@mock.patch('os.path.exists', autospec=True)
def test_get_tshark_path(mock_exists):
    mock_exists.return_value = True
    actual = tshark.get_process_path("/some/path/tshark")
    expected = "/some/path/tshark"
    assert actual == expected


@mock.patch('subprocess.check_output', autospec=True)
def test_get_tshark_version(mock_check_output):
    mock_check_output.return_value = (
        b'TShark 1.12.1 (Git Rev Unknown from unknown)\n\n'b'Copyright '
        b'1998-2014 Gerald Combs <gerald@wireshark.org> and contributors.\n'
    )
    actual = tshark.get_tshark_version()
    expected = version.parse('1.12.1')
    assert actual == expected


def test_get_display_filter_flag():
    actual = tshark.get_tshark_display_filter_flag(version.parse('1.10.0'))
    expected = '-Y'
    assert actual == expected

    actual = tshark.get_tshark_display_filter_flag(version.parse('1.6.0'))
    expected = '-R'
    assert actual == expected


@mock.patch('subprocess.check_output', autospec=True)
def test_get_tshark_interfaces(mock_check_output):
    mock_check_output.return_value = (
        b'1. wlan0\n2. any\n3. lo (Loopback)\n4. eth0\n5. docker0\n'
    )
    actual = tshark.get_tshark_interfaces()
    expected = ['wlan0', 'any', 'lo', 'eth0', 'docker0']
    assert actual == expected

