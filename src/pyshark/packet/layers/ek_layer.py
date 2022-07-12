import abc
import os
import io

import typing

from pyshark.packet.common import colored
from pyshark import ek_field_mapping
from pyshark.packet.layers.base import BaseLayer


class _EkLayerHelperFuncsMixin(abc.ABC):
    """For methods shared between the EK layer and sublayers"""

    def get_field_as_list(self, name) -> list:
        """Helper function to get a certain field always as a list.

        Some fields may appear once or more in the packet. The field will appear as a list if it appears more
        than once. In order to avoid checking certain fields if they're lists or not, this function will
        return the field inside a list at all times.

        For example, in a DNS packet there may be one or more responses.
        A packet with with one response (www.google.com) will return:
            >>> print(pkt.dns.resp_name)
            "www.google.com"
        While a packet with two responses will return:
            >>> print(pkt.dns.resp_name)
            ["www.google.com", "www.google2.com"]

        To avoid this changing behaviour, use:
            >>> print(pkt.dns.get_field_as_list("resp_name"))
            ["www.google.com"]
        """
        field_value = self.get_field(name)
        if isinstance(field_value, list):
            return field_value
        return [field_value]


class EkLayer(BaseLayer, _EkLayerHelperFuncsMixin):
    __slots__ = ["_layer_name", "_fields_dict"]

    def __init__(self, layer_name, layer_dict):
        super().__init__(layer_name)
        self._fields_dict = layer_dict

    def get_field(self, name) -> typing.Union["EkMultiField", None, str, int, bool, bytes, list]:
        name = name.replace(".", "_")
        if name in self._fields_dict:
            # For cases like "text"
            return self._get_field_value(name)

        for prefix in self._get_possible_layer_prefixes():
            nested_field = self._get_nested_field(prefix, name)
            if nested_field is not None:
                return nested_field

        return None

    def has_field(self, name) -> bool:
        """Checks if the field exists, either a nested field or a regular field"""
        return name in self.field_names or name in self.all_field_names

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

    def _get_field_value(self, full_field_name):
        """Gets the field value, optionally casting it using the cached field mapping"""
        field_value = self._fields_dict[full_field_name]
        return ek_field_mapping.MAPPING.cast_field_value(self._layer_name, full_field_name, field_value)

    def _get_nested_field(self, prefix, name):
        """Gets a field that is directly on the layer

        Returns either a multifield or a raw value.
        """
        # TODO: Optimize
        field_ek_name = f"{prefix}_{name}"
        if field_ek_name in self._fields_dict:
            if self._field_has_subfields(field_ek_name):
                return EkMultiField(self, self._fields_dict, name,
                                    value=self._get_field_value(field_ek_name))
            return self._get_field_value(field_ek_name)

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

    def _pretty_print_layer_fields(self, file: io.IOBase):
        for field_name in self.field_names:
            field = self.get_field(field_name)
            self._pretty_print_field(field_name, field, file, indent=1)

    def _pretty_print_field(self, field_name, field, file, indent=0):
        prefix = "\t" * indent
        if isinstance(field, EkMultiField):
            file.write(colored(f"{prefix}{field_name}: ", "green", attrs=["bold"]))
            if field.value is not None:
                file.write(str(field.value))
            file.write(os.linesep)
            for subfield in field.subfields:
                self._pretty_print_field(subfield, field.get_field(subfield), file,
                                         indent=indent + 1)
        else:
            file.write(colored(f"{prefix}{field_name}: ", "green", attrs=["bold"]))
            file.write(f"{field}{os.linesep}")

    def _get_possible_layer_prefixes(self):
        """Gets the possible prefixes for a field under this layer.

        The order matters, longest must be first
        """
        return [f"{self._layer_name}_{self._layer_name}", self._layer_name]


class EkMultiField(_EkLayerHelperFuncsMixin):
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
