# TODO: Inherit from interface
import os

from pyshark.packet.common import SlotsPickleable
from pyshark.packet.layer import Layer


class EkLayer(Layer):
    __slots__ = ["_layer_name", "_fields_dict"]

    # TODO: remove
    raw_mode = False

    def __init__(self, layer_name, layer_dict):
        self._layer_name = layer_name
        self._fields_dict = layer_dict

    def get_field(self, name):
        if name in self._fields_dict:
            # For cases like "text"
            return self._fields_dict[name]
        field_ek_name = f"{self._ek_layer_prefix}_{name}"
        if field_ek_name in self._fields_dict:
            if self._field_has_subfields(field_ek_name):
                return EkMultiField(self, field_ek_name, self._fields_dict[field_ek_name])
            return self._fields_dict[field_ek_name]
        return None

    @property
    def field_names(self):
        names = []
        for field_name in self._fields_dict:
            name_without_prefix = _remove_ek_prefix(self._ek_layer_prefix, field_name)
            if "_" not in name_without_prefix:
                # Don't take sub-fields, only immediate children
                names.append(name_without_prefix)
        return names

    @property
    def _ek_layer_prefix(self):
        return f"{self._layer_name}_{self._layer_name}"

    def _field_has_subfields(self, field_ek_name):
        # TODO: Optimize
        field_ek_name_with_ext = f"{field_ek_name}_"
        for field_name in self._fields_dict:
            if field_name.startswith(field_ek_name_with_ext):
                return True
        return False

    # TODO: Redo these parts in the baseclass
    def _get_all_field_lines(self):
        """Returns all lines that represent the fields of the layer (both their names and values)."""
        for field in self.field_names:
            yield from self._get_field_or_layer_repr(field)

    def _get_field_repr(self, field):
        field_value = self.get_field(field)
        if not isinstance(field_value, EkMultiField):
            return field_value
        field_repr = f"{field_value.value}{os.linesep}"
        for subfield in field_value.subfields:
            field_repr += f"\t {subfield}: {field_value.get_field(subfield)}"
        return field_repr


class EkMultiField:
    __slots__ = ["_containing_layer", "_field_ek_name", "value"]

    def __init__(self, containing_layer, field_ek_name, field_value):
        self._containing_layer = containing_layer
        self._field_ek_name = field_ek_name
        self.value = field_value

    def get_field(self, field_name):
        return self._containing_layer.get_field(f"{self._field_ek_name}_{field_name}")

    @property
    def subfields(self):
        subfield_names = []
        # TODO: Don't access internal
        for field in self._containing_layer._fields_dict:
            if field != self._field_ek_name and field.startswith(self._field_ek_name):
                subfield_names.append(_remove_ek_prefix(self._field_ek_name, field))
        return subfield_names

    def __getattr__(self, item):
        return self.get_field(item)


def _remove_ek_prefix(prefix, value):
    """Removes prefix given and the underscore after it"""
    return value[len(prefix) + 1:]
