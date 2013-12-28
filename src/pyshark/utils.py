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
