class PacketSummary(object):
    """A simple object containing a psml summary.

    Can contain various summary information about a packet.
    """

    def __init__(self, structure, values):
        self._fields = {}
        self._field_order = []

        for key, val in zip(structure, values):
            key, val = str(key), str(val)
            self._fields[key] = val
            self._field_order.append(key)
            setattr(self, key.lower().replace('.', '').replace(',', ''), val)

    def __repr__(self):
        protocol, src, dst = self._fields.get('Protocol', '?'), self._fields.get('Source', '?'),\
                             self._fields.get('Destination', '?')
        return f'<{self.__class__.__name__} {protocol}: {src} to {dst}>'

    def __str__(self):
        return self.summary_line

    @property
    def summary_line(self) -> str:
        return ' '.join([self._fields[key] for key in self._field_order])
