import binascii
import typing

from pyshark.packet.common import Pickleable, SlotsPickleable


class LayerField(SlotsPickleable):
    """Holds all data about a field of a layer, both its actual value and its name and nice representation."""

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
        return f'<LayerField {self.name}: {self.get_default_value()}>'

    def get_default_value(self) -> str:
        """Gets the best 'value' string this field has."""
        val = self.show
        if not val:
            val = self.raw_value
        if not val:
            val = self.showname
        return val

    @property
    def showname_value(self) -> typing.Union[str, None]:
        """The "pretty value" (as displayed by Wireshark) of the field."""
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ', 1)[1]
        return None

    @property
    def showname_key(self) -> typing.Union[str, None]:
        """The "pretty name" (as displayed by Wireshark) of the field."""
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ', 1)[0]
        return None

    @property
    def binary_value(self) -> bytes:
        """Converts this field to binary (assuming it's a binary string)"""
        str_raw_value = str(self.raw_value)
        if len(str_raw_value) % 2 == 1:
            str_raw_value = '0' + str_raw_value

        return binascii.unhexlify(str_raw_value)

    @property
    def int_value(self) -> int:
        """Returns the int value of this field (assuming it's represented as a decimal integer)."""
        return int(self.raw_value)

    @property
    def hex_value(self) -> int:
        """Returns the int value of this field if it's in base 16

        (either as a normal number or in a "0xFFFF"-style hex value)
        """
        return int(self.raw_value, 16)

    base16_value = hex_value


class LayerFieldsContainer(str, Pickleable):
    """An object which contains one or more fields (of the same name).

    When accessing member, such as showname, raw_value, etc. the appropriate member of the main (first) field saved
    in this container will be shown.
    """

    def __new__(cls, main_field, *args, **kwargs):
        if hasattr(main_field, 'get_default_value'):
            obj = str.__new__(cls, main_field.get_default_value(), *args, **kwargs)
        else:
            obj = str.__new__(cls, main_field, *args, **kwargs)
        obj.fields = [main_field]
        return obj

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + dir(self.main_field)

    def add_field(self, field):
        self.fields.append(field)

    @property
    def all_fields(self):
        """Returns all fields in a list, the main field followed by the alternate fields."""
        return self.fields

    @property
    def main_field(self):
        return self.fields[0]

    @property
    def alternate_fields(self):
        """Return the alternate values of this field containers (non-main ones)."""
        return self.fields[1:]

    def __getattr__(self, item):
        return getattr(self.main_field, item)
