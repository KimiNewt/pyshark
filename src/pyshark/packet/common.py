class Pickleable(object):
    """
    Base class that implements getstate/setstate, since most of the classes are overriding getattr.
    """

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)