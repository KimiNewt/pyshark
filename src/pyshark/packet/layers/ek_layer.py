import os

import py
import typing

from pyshark.packet.layers.base import BaseLayer


class EkLayer(BaseLayer):
    __slots__ = ["_layer_name", "_fields_dict"]

    def __init__(self, layer_name, layer_dict):
        super().__init__(layer_name)
        self._fields_dict = layer_dict

    def get_field(self, name) -> typing.Union["EkMultiField", None, str, int, bool]:
        name = name.replace(".", "_")
        if name in self._fields_dict:
            # For cases like "text"
            return self._fields_dict[name]

        for prefix in self._get_possible_layer_prefixes():
            nested_field = self._get_nested_field(prefix, name)
            if nested_field is not None:
                return nested_field

        return None

    @property
    def field_names(self):
        return list({field_name.split("_", 1)[0] for field_name in self.all_field_names})

    @property
    def all_field_names(self):
        """Gets all field names, including subfields"""
        names = set()
        for field_name in self._fields_dict:
            for prefix in self._get_possible_layer_prefixes():
                if field_name.startswith(prefix):
                    names.add(_remove_ek_prefix(prefix, field_name))
                    break
        return list(names)

    def _get_nested_field(self, prefix, name):
        """Gets a field that is directly on the layer

        Returns either a multifield or a raw value.
        """
        # TODO: Optimize
        field_ek_name = f"{prefix}_{name}"
        if field_ek_name in self._fields_dict:
            if self._field_has_subfields(field_ek_name):
                return EkMultiField(self, self._fields_dict, name,
                                    value=self._fields_dict[field_ek_name])
            return self._fields_dict[field_ek_name]

        for possible_nested_name in self._fields_dict:
            if possible_nested_name.startswith(f"{field_ek_name}_"):
                return EkMultiField(self, self._fields_dict, name, value=None)

        return None

    def _field_has_subfields(self, field_ek_name):
        field_ek_name_with_ext = f"{field_ek_name}_"
        for field_name in self._fields_dict:
            if field_name.startswith(field_ek_name_with_ext):
                return True
        return False

    def _pretty_print_layer_fields(self, terminal_writer: py.io.TerminalWriter):
        for field_name in self.field_names:
            field = self.get_field(field_name)
            self._pretty_print_field(field_name, field, terminal_writer, indent=1)

    def _pretty_print_field(self, field_name, field, terminal_writer, indent=0):
        prefix = "\t" * indent
        if isinstance(field, EkMultiField):
            terminal_writer.write(f"{prefix}{field_name}: ", green=True, bold=True)
            if field.value:
                terminal_writer.write(field.value)
            terminal_writer.write(os.linesep)
            for subfield in field.subfields:
                self._pretty_print_field(subfield, field.get_field(subfield), terminal_writer,
                                         indent=indent + 1)
        else:
            terminal_writer.write(f"{prefix}{field_name}: ", green=True, bold=True)
            terminal_writer.write(f"{field}{os.linesep}")

    def _get_possible_layer_prefixes(self):
        """Gets the possible prefixes for a field under this layer.

        The order matters, longest must be first
        """
        return [f"{self._layer_name}_{self._layer_name}", self._layer_name]


class EkMultiField:
    __slots__ = ["_containing_layer", "_full_name", "_all_fields", "value"]

    def __init__(self, containing_layer: EkLayer, all_fields, full_name, value=None):
        self._containing_layer = containing_layer
        self._full_name = full_name
        self._all_fields = all_fields
        self.value = value

    def get_field(self, field_name):
        return self._containing_layer.get_field(f"{self._full_name}_{field_name}")

    @property
    def subfields(self):
        names = set()
        for field_name in self._containing_layer.all_field_names:
            if field_name != self._full_name and field_name.startswith(f"{self._full_name}_"):
                names.add(field_name[len(self._full_name):].split("_")[1])
        return list(names)

    @property
    def field_name(self):
        return self._full_name.split("_")[-1]

    def __getattr__(self, item):
        value = self.get_field(item)
        if value is None:
            raise AttributeError(f"Subfield {item} not found")
        return value

    def __repr__(self):
        value = f": {self.value}" if self.value else ""
        return f"<EkMultiField {self.field_name}{value}>"

    def __dir__(self) -> typing.Iterable[str]:
        return dir(type(self)) + self.subfields


def _remove_ek_prefix(prefix, value):
    """Removes prefix given and the underscore after it"""
    return value[len(prefix) + 1:]


def _get_subfields(all_fields, field_ek_name):
    subfield_names = []
    for field in all_fields:
        if field != field_ek_name and field.startswith(field_ek_name):
            subfield_names.append(_remove_ek_prefix(field_ek_name, field))
    return subfield_names
