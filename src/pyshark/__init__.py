import sys


class UnsupportedVersionException(Exception):
    pass


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    raise UnsupportedVersionException("Your version of Python is unsupported. "
                                      "Pyshark requires Python >= 3.5 & Wireshark >= 2.2.0. "
                                      " Please upgrade or use pyshark-legacy, or pyshark version 0.3.8")

from pyshark.capture.live_capture import LiveCapture
from pyshark.capture.live_ring_capture import LiveRingCapture
from pyshark.capture.file_capture import FileCapture
from pyshark.capture.remote_capture import RemoteCapture
from pyshark.capture.inmem_capture import InMemCapture
