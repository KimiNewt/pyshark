import inspect
import threading
import ctypes

def file_or_path(func):
    """
    A decorator which checks whether the first parameter is a string or a file, if it is a string, replaces it with
    a file with that path.
    """

    def wrapper(*args, **kwargs):
        filepath = args[0]
        args = args[1:]
        if isinstance(filepath, basestring):
            filepath = file(filepath, 'rb')
        return func(filepath, *args, **kwargs)


def _async_raise(tid, exctype):
    """
    Raises an exception in the threads with id tid
    """
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid),
                                                  ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # "if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, 0)
        raise SystemError("PyThreadState_SetAsyncExc failed")


class StoppableThread(threading.Thread):
    """
    A thread class that supports raising exception in the thread from
    another thread.

    Taken from http://stackoverflow.com/questions/323972/is-there-any-way-to-kill-a-thread-in-python
    """

    def _get_my_tid(self):
        """
        Determines this (self's) thread id

        CAREFUL : this function is executed in the context of the caller
        thread, to get the identity of the thread represented by this
        instance.
        """
        if not self.is_alive():
            raise threading.ThreadError("the thread is not active")

        for tid, tobj in threading._active.iteritems():
            if tobj is self:
                return tid
        raise AssertionError('Could not determine thread ID')

    def raise_exc(self, exctype):
        """
        Raises the given exception type in the context of this thread.

        If the thread is busy in a system call (time.sleep(),
        socket.accept(), ...), the exception is simply ignored.

        If you are sure that your exception should terminate the thread,
        one way to ensure that it works is:

            t = ThreadWithExc( ... )
            ...
            t.raiseExc( SomeException )
            while t.isAlive():
                time.sleep( 0.1 )
                t.raiseExc( SomeException )

        If the exception is to be caught by the thread, you need a way to
        check that your thread has caught it.

        CAREFUL : this function is executed in the context of the
        caller thread, to raise an excpetion in the context of the
        thread represented by this instance.
        """
        _async_raise(self._get_my_tid(), exctype)

    def exit_thread(self):
        self.raise_exc(SystemExit)

class StopSubprocess(Exception):
    pass

