import asyncio
import os
from types import SimpleNamespace

try:
    import mock
except ModuleNotFoundError:
    from unittest import mock
import pytest

import pyshark
from pyshark.capture import live_capture
from pyshark.capture.capture import Capture


@pytest.fixture(params=[["wlan0"], ["wlan0mon", "wlan1mon"]])
def interfaces(request):
    with mock.patch("pyshark.tshark.tshark.get_tshark_interfaces", return_value=request.param):
        yield request.param


@pytest.fixture
def capture(interfaces):
    return pyshark.LiveCapture(interface=interfaces)


@pytest.mark.parametrize("monitoring", [True, False])
def test_get_dumpcap_interface_parameter(capture, monitoring, interfaces):
    # type: (pyshark.LiveCapture, bool, list) -> None
    capture.monitor_mode = monitoring
    dumpcap_parameters = capture._get_dumpcap_parameters()
    dumpcap_interfaces = [dumpcap_parameters[index + 1]
                          for index, value in enumerate(dumpcap_parameters)
                          if value == "-i"]
    assert dumpcap_interfaces == interfaces


def _capture_with_loop():
    loop = asyncio.new_event_loop()
    with mock.patch("pyshark.capture.live_capture.get_tshark_interfaces", return_value=["wlan0"]):
        capture = pyshark.LiveCapture(interface="wlan0", eventloop=loop)
    return capture, loop


def _patch_pipe(monkeypatch, fds):
    closed = []
    real_close = os.close

    def fake_close(fd):
        if fd in fds:
            closed.append(fd)
        else:
            real_close(fd)

    monkeypatch.setattr(live_capture, "os", SimpleNamespace(pipe=lambda: fds, close=fake_close))
    return closed


def _prepare_capture(monkeypatch, capture, fake_process, fake_super):
    async def fake_create(*args, **kwargs):
        return fake_process

    monkeypatch.setattr(live_capture, "asyncio", SimpleNamespace(create_subprocess_exec=fake_create))
    monkeypatch.setattr(live_capture, "get_process_path", lambda **kwargs: "dumpcap")
    monkeypatch.setattr(Capture, "_get_tshark_process", fake_super)
    monkeypatch.setattr(capture, "_get_dumpcap_parameters", lambda: [])
    monkeypatch.setattr(capture, "_create_stderr_handling_task", lambda stderr: None)
    monkeypatch.setattr(capture, "_created_new_process", lambda *args, **kwargs: None)


def test_get_tshark_process_closes_both_pipe_ends(monkeypatch):
    capture, loop = _capture_with_loop()
    fake_process = SimpleNamespace(returncode=None, stderr=object(), pid=123)
    closed = _patch_pipe(monkeypatch, (10, 11))

    async def fake_super(self, packet_count=None, stdin=None):
        assert stdin == 10
        return fake_process

    _prepare_capture(monkeypatch, capture, fake_process, fake_super)

    try:
        result = loop.run_until_complete(capture._get_tshark_process())
        assert result is fake_process
        assert closed == [11, 10]
    finally:
        loop.close()


def test_get_tshark_process_closes_pipe_ends_on_failure(monkeypatch):
    capture, loop = _capture_with_loop()
    fake_process = SimpleNamespace(returncode=None, stderr=object(), pid=123)
    closed = _patch_pipe(monkeypatch, (12, 13))

    async def fake_super(self, packet_count=None, stdin=None):
        raise RuntimeError("tshark failed")

    _prepare_capture(monkeypatch, capture, fake_process, fake_super)

    try:
        with pytest.raises(RuntimeError):
            loop.run_until_complete(capture._get_tshark_process())
        assert closed == [13, 12]
    finally:
        loop.close()
