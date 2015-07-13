import mock

from pyshark.tshark.tshark import (
    get_tshark_display_filter_flag,
    get_tshark_interfaces,
    get_tshark_version,
    get_tshark_path,
)


@mock.patch('os.path.exists', autospec=True)
def test_get_tshark_path(mock_exists):
    mock_exists.return_value = True
    actual = get_tshark_path("/some/path/tshark")
    expected = "/some/path/tshark"
    assert actual == expected


@mock.patch('pyshark.tshark.tshark.check_output', autospec=True)
def test_get_tshark_version(mock_check_output):
    mock_check_output.return_value = (
        b'TShark 1.12.1 (Git Rev Unknown from unknown)\n\n'b'Copyright '
        b'1998-2014 Gerald Combs <gerald@wireshark.org> and contributors.\n'
    )
    actual = get_tshark_version()
    expected = '1.12.1'
    assert actual == expected

@mock.patch('pyshark.tshark.tshark.get_tshark_version', autospec=True)
def test_get_display_filter_flag(mock_get_tshark_version):
    mock_get_tshark_version.return_value = '1.10.0'
    actual = get_tshark_display_filter_flag()
    expected = '-Y'
    assert actual == expected

    mock_get_tshark_version.return_value = '1.6.0'
    actual = get_tshark_display_filter_flag()
    expected = '-R'
    assert actual == expected

@mock.patch('pyshark.tshark.tshark.check_output', autospec=True)
def test_get_tshark_interfaces(mock_check_output):
    mock_check_output.return_value = (
        b'1. wlan0\n2. any\n3. lo (Loopback)\n4. eth0\n5. docker0\n'
    )
    actual = get_tshark_interfaces()
    expected = ['1', '2', '3', '4', '5']
    assert actual == expected

