# Temporary work arounds for depreciated classes related to child watching
# in UNIX asyncio event loops. 

import asyncio
import threading
import os 
import signal
import warnings

from asyncio import events
from asyncio import unix_events
from asyncio import log

class NewSafeChildWatcher:
    '''Re-implementation of SafeChildWatcher.

    Methods taken from both SafeChildWatcher and parent
    class BaseChildWatcher in asyncio/unix_events.py
    '''

    def __init__(self):
        self._loop = None
        self._callbacks = {}

    def close(self):
        self.attach_loop(None)

    def __enter__(self):
        return self
    
    def __exit__(self, a, b, c):
        pass

    def is_active(self):
        return self._loop is not None and self._loop.is_running()

    def add_child_handler(self, pid, callback, *args):
        self._callbacks[pid] = (callback, args)
        self._do_waitpid(pid)

    def remove_child_handler(self, pid):
        try:
            del self._callbacks[pid]
            return True
        except KeyError:
            return False
        
    def _do_waitpid_all(self):

        for pid in list(self._callbacks):
            self._do_waitpid(pid)
    
    def _do_waitpid(self, expected_pid):
        assert expected_pid > 0

        try:
            pid, status = os.waitpid(expected_pid, os.WNOHANG)
        except ChildProcessError:
            pid = expected_pid
            returncode = 255
            log.logger.warning(
                "Unknown child process pid %d, will report returncode 255",
                pid)
        else:
            if pid == 0:
                return

            returncode = os.waitstatus_to_exitcode(status)
            if self._loop.get_debug():
                log.logger.debug('process %s exited with returncode %s',
                             expected_pid, returncode)

        try:
            callback, args = self._callbacks.pop(pid)
        except KeyError: 
            if self._loop.get_debug():
                log.logger.warning("Child watcher got an unexpected pid: %r",
                               pid, exc_info=True)
        else:
            callback(pid, returncode, *args)

    def attach_loop(self, loop):
        assert loop is None or isinstance(loop, events.AbstractEventLoop)

        if self._loop is not None and loop is None and self._callbacks:
            warnings.warn(
                'A loop is being detached '
                'from a child watcher with pending handlers',
                RuntimeWarning)

        if self._loop is not None:
            self._loop.remove_signal_handler(signal.SIGCHLD)

        self._loop = loop
        if loop is not None:
            loop.add_signal_handler(signal.SIGCHLD, self._sig_chld)
            self._do_waitpid_all()
    
    def _sig_chld(self):
        try:
            self._do_waitpid_all()
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._loop.call_exception_handler({
                'message': 'Unknown exception in SIGCHLD handler',
                'exception': exc,
            })


# Also from asyncio/unix_events.py
def can_use_pidfd():
    if not hasattr(os, 'pidfd_open'):
        return False
    try:
        pid = os.getpid()
        os.close(os.pidfd_open(pid, 0))
    except OSError:
        return False
    return True

class NewUnixDefaultEventPolicy(events.BaseDefaultEventLoopPolicy):
    '''Re-implementation of _UnixDefaultEventPolicy from asyncio/unix_events.py

    Overrides get_child_watcher() and set_child_watcher() methods
    '''
    _loop_factory = unix_events._UnixSelectorEventLoop

    def __init__(self):
        super().__init__()
        self._watcher = None

    def _init_watcher(self):
        with threading.Lock():
            if self._watcher is None:
                if can_use_pidfd():
                    self._watcher = unix_events.PidfdChildWatcher()
                else:
                    self._watcher = NewSafeChildWatcher()

    def set_event_loop(self, loop: asyncio.AbstractEventLoop | None):
        super().set_event_loop(loop)
        if (self._watcher is not None and
                threading.current_thread() is threading.main_thread()):
            self._watcher.attach_loop(loop)
    
    def get_child_watcher(self):
        if self._watcher is None:
            self._init_watcher()
        return self._watcher
    
    def set_child_watcher(self, watcher):
        assert self._watcher is None or isinstance(watcher, unix_events.PidfdChildWatcher) or isinstance(watcher, NewSafeChildWatcher)

        if self._watcher is not None:
            self._watcher.close()
        self._watcher = watcher
    