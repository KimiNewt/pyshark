import os
import typing
import io
import sys

from pyshark.packet import common

DATA_LAYER_NAME = "DATA"


class BaseLayer(common.SlotsPickleable):
    """An object representing a Packet layer."""
    __slots__ = ["_layer_name"]

    def __init__(self, layer_name):
        self._layer_name = layer_name

    def get_field(self, name):
        raise NotImplementedError()

    @property
    def field_names(self) -> typing.List[str]:
        """Gets all XML field names of this layer."""
        raise NotImplementedError()

    def has_field(self, name):
        return name in self.field_names

    @property
    def layer_name(self):
        return self._layer_name

    def get(self, item, default=None):
        """Gets a field in the layer, or the default if not found.

        Works the same way as getattr, but returns the given default if not the field was not found"""
        try:
            return getattr(self, item)
        except AttributeError:
            return default

    def __dir__(self):
        return dir(type(self)) + self.field_names

    def __getattr__(self, item):
        val = self.get_field(item)
        if val is None:
            raise AttributeError(f"{item} does not exist in Layer")
        return val

    def pretty_print(self, writer=None):
        if not writer:
            writer = sys.stdout
        if self.layer_name == DATA_LAYER_NAME:
            writer.write('DATA')
            return

        text = f'Layer {self.layer_name.upper()}{os.linesep}:'
        writer.write(common.colored(text, color="yellow", attrs=["bold"]))
        self._pretty_print_layer_fields(writer)

    def _pretty_print_layer_fields(self, terminal_writer: io.IOBase):
        raise NotImplementedError()

    def __repr__(self):
        return f'<{self.layer_name.upper()} Layer>'

    def __str__(self):
        writer = io.StringIO()
        self.pretty_print(writer=writer)
        return writer.getvalue()
