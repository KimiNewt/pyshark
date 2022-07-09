class Pickleable(object):
    """
    Base class that implements getstate/setstate, since most of the classes are overriding getattr.
    """

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)


class SlotsPickleable(object):
    __slots__ = []

    def __getstate__(self):
        ret = {}
        for slot in self.__slots__:
            ret[slot] = getattr(self, slot)
        return ret

    def __setstate__(self, data):
        for key, val in data.items():
            setattr(self, key, val)


class StrWriter:
    """A class which mocks the py.io.TerminalWriter to write to an internal buffer"""

    def __init__(self):
        self.buffer = ""

    def write(self, text, *_, **__):
        self.buffer += text
