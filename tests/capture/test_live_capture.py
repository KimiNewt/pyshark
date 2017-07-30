import pytest
import pyshark

@pytest.fixture
def capture():
    return pyshark.LiveCapture()

@pytest.mark.parametrize("interfaces", [["wlan0"]])
@pytest.mark.parametrize("monitoring", [True, False])
def test_get_dumpcap_interface_parameter(capture, monitoring, interfaces):
    #type: (pyshark.LiveCapture, bool, list) -> None
    capture.monitor_mode = monitoring
    capture.interfaces = interfaces
    dumpcap_parameters = capture._get_dumpcap_parameters()
    dumpcap_interfaces = [ dumpcap_parameters[index+1]
                           for index, value in enumerate(dumpcap_parameters)
                           if value == "-i" ]
    assert dumpcap_interfaces == interfaces
