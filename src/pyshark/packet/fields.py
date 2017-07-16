import binascii

from pyshark.packet.common import Pickleable, SlotsPickleable


class LayerField(SlotsPickleable):
    """
    Holds all data about a field of a layer, both its actual value and its name and nice representation.
    """
    # Note: We use this object with slots and not just a dict because
    # it's much more memory-efficient (cuts about a third of the memory).
    __slots__ = ['name', 'showname', 'raw_value', 'show', 'hide', 'pos', 'size', 'unmaskedvalue']

    def __init__(self, name=None, showname=None, value=None, show=None, hide=None, pos=None, size=None, unmaskedvalue=None):
        self.name = name
        self.showname = showname
        self.raw_value = value
        self.show = show
        self.pos = pos
        self.size = size
        self.unmaskedvalue = unmaskedvalue

        if hide and hide == 'yes':
            self.hide = True
        else:
            self.hide = False

    def __repr__(self):
        return '<LayerField %s: %s>' % (self.name, self.get_default_value())

    def get_default_value(self):
        """
        Gets the best 'value' string this field has.
        """
        val = self.show
        if not val:
            val = self.raw_value
        if not val:
            val = self.showname
        return val

    @property
    def showname_value(self):
        """
        For fields which do not contain a normal value, we attempt to take their value from the showname.
        """
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ', 1)[1]

    @property
    def showname_key(self):
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ', 1)[0]

    @property
    def binary_value(self):
        """
        Converts this field to binary (assuming it's a binary string)
        """
        return binascii.unhexlify(self.raw_value)

    @property
    def int_value(self):
        """
        Returns the int value of this field (assuming it's an integer integer).
        """
        return int(self.raw_value)

    @property
    def hex_value(self):
        """
        Returns the int value of this field if it's in base 16 (either as a normal number or in
        a "0xFFFF"-style hex value)
        """
        return int(self.raw_value, 16)

    base16_value = hex_value


class LayerFieldsContainer(str, Pickleable):
    """
    An object which contains one or more fields (of the same name).
    When accessing member, such as showname, raw_value, etc. the appropriate member of the main (first) field saved
    in this container will be shown.
    """

    def __new__(cls, main_field, *args, **kwargs):
        value = main_field.get_default_value()
        if value is None:
            value = ''
        obj = str.__new__(cls, value, *args, **kwargs)
        obj.fields = [main_field]
        return obj

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + dir(self.main_field)

    def add_field(self, field):
        self.fields.append(field)

    @property
    def main_field(self):
        return self.fields[0]

    @property
    def alternate_fields(self):
        """
        Return the alternate values of this field containers (non-main ones).
        """
        return self.fields[1:]

    @property
    def all_fields(self):
        """
        Returns all fields in a list, the main field followed by the alternate fields.
        """
        return self.fields

    def __getattr__(self, item):
        return getattr(self.main_field, item)