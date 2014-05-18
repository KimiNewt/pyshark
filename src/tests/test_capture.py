import pyshark
import webbrowser

def test_capture_packets():
    """Test to make sure TShark can capture packets from an interface"""
    capture = pyshark.LiveCapture(interface="all")
    it = capture.sniff_continuously(packet_count=5)
    __ = webbrowser.open("https://www.python.org")
    packet_count = sum(1 for packet in it)
    
    assert packet_count == 5