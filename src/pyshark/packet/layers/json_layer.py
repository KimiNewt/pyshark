import os
import io

from pyshark.packet.common import colored
from pyshark.packet.fields import LayerField
from pyshark.packet.fields import LayerFieldsContainer
from pyshark.packet.layers.base import BaseLayer


class JsonLayer(BaseLayer):
    __slots__ = [
        "duplicate_layers",
        "_showname_fields_converted_to_regular",
        "_full_name",
        "_is_intermediate",
        "_wrapped_fields",
        "value",
        "_all_fields"
    ] + BaseLayer.__slots__

    def __init__(self, layer_name, layer_dict, full_name=None, is_intermediate=False):
        """Creates a JsonLayer. All sublayers and fields are created lazily later."""
        super().__init__(layer_name)
        self.duplicate_layers = []
        self._showname_fields_converted_to_regular = False
        if not full_name:
            self._full_name = self._layer_name
        else:
            self._full_name = full_name
        self._is_intermediate = is_intermediate
        self._wrapped_fields = {}
        if isinstance(layer_dict, list):
            self.duplicate_layers = [JsonLayer(layer_name, duplicate_dict,
                                               full_name=full_name, is_intermediate=is_intermediate)
                                     for duplicate_dict in layer_dict[1:]]
            layer_dict = layer_dict[0]
        if not isinstance(layer_dict, dict):
            self.value = layer_dict
            self._all_fields = {}
            return

        self._all_fields = layer_dict

    def get_field(self, name):
        """Gets a field by its full or partial name."""
        # We only make the wrappers here (lazily) to avoid creating a ton of objects needlessly.
        self._convert_showname_field_names_to_field_names()
        field = self._wrapped_fields.get(name)
        if field is None:
            is_fake = False
            field = self._get_internal_field_by_name(name)
            if field is None:
                # Might be a "fake" field in JSON
                is_fake = self._is_fake_field(name)
                if not is_fake:
                    raise AttributeError(f"No such field {name}")
            field = self._make_wrapped_field(name, field, is_fake=is_fake)
            self._wrapped_fields[name] = field
        return field

    @property
    def field_names(self):
        self._convert_showname_field_names_to_field_names()
        return list(set([self._sanitize_field_name(name) for name in self._all_fields
                         if name.startswith(self._full_name)] +
                        [name.rsplit('.', 1)[1] for name in self._all_fields if '.' in name]))

    def has_field(self, dotted_name) -> bool:
        """Checks whether the layer has the given field name.

        Can get a dotted name, i.e. layer.sublayer.subsublayer.field
        """
        parts = dotted_name.split('.')
        cur_layer = self
        for part in parts:
            if part in cur_layer.field_names:
                cur_layer = cur_layer.get_field(part)
            else:
                return False
        return True

    def _pretty_print_layer_fields(self, file: io.IOBase):
        for field_line in self._get_all_field_lines():
            if ':' in field_line:
                field_name, field_line = field_line.split(':', 1)
                file.write(colored(field_name + ':', "green", ["bold"]))
            file.write(colored(field_line, attrs=["bold"]))

    def _get_all_field_lines(self):
        """Returns all lines that represent the fields of the layer (both their names and values)."""
        for field in self._get_all_fields_with_alternates():
            yield from self._get_field_or_layer_repr(field)

    def _get_field_or_layer_repr(self, field):
        if isinstance(field, JsonLayer):
            yield "\t" + field.layer_name + ":" + os.linesep
            for line in field._get_all_field_lines():
                yield "\t" + line
        elif isinstance(field, list):
            for subfield_or_layer in field:
                yield from self._get_field_or_layer_repr(subfield_or_layer)
        else:
            yield f"\t{self._sanitize_field_name(field.name)}: {field.raw_value}{os.linesep}"

    def _sanitize_field_name(self, field_name):
        return field_name.replace(self._full_name + '.', '')

    def _field_name_from_showname(self, field_name):
        """Converts a 'showname'-like field key to a regular field name

        Sometimes in the JSON, there are "text" type fields which might look like this:
        "my_layer":
            {
                "my_layer.some_field": 1,
                "Something Special: it's special": {
                    "my_layer.special_field": "it's special"
                }
            }

        We convert the showname key into the field name. The internals will turn into a fake layer.
        In this case the field will be accessible by pkt.my_layer.something_special.special_field
        """
        showname_key = field_name.split(":", 1)[0]
        return self._full_name + "." + showname_key.lower().replace(" ", "_")

    def _get_all_fields_with_alternates(self):
        return [self.get_field(name) for name in self.field_names]

    def _convert_showname_field_names_to_field_names(self):
        """Converts all fields that don't have a proper name (they have a showname name) to a regular name

        See self._field_name_from_showname docs for more.
        """
        if self._showname_fields_converted_to_regular:
            return
        for field_name in list(self._all_fields):
            if ":" in field_name:
                field_value = self._all_fields.pop(field_name)
                if isinstance(field_value, dict):
                    # Save the showname
                    field_value["showname"] = field_name
                # Convert the old name to the new name.
                self._all_fields[
                    self._field_name_from_showname(field_name)] = field_value

        self._showname_fields_converted_to_regular = True

    def _get_internal_field_by_name(self, name):
        """Gets the field by name, or None if not found."""
        field = self._all_fields.get(name, self._all_fields.get(f"{self._full_name}.{name}"))
        if field is not None:
            return field
        for field_name in self._all_fields:
            # Specific name
            if field_name.endswith(f'.{name}'):
                return self._all_fields[field_name]

    def _is_fake_field(self, name):
        # Some fields include parts that are not reflected in the JSON dictionary
        # i.e. a possible json is:
        # {
        #   foo: {
        #           foo.bar.baz: {
        #                   foo.baz: 3
        #               }
        # }
        # So in this case we must create a fake layer for "bar".
        field_full_name = f"{self._full_name}.{name}."
        for name, field in self._all_fields.items():
            if name.startswith(field_full_name):
                return True
        return False

    def _make_wrapped_field(self, name, field, is_fake=False, full_name=None):
        """Creates the field lazily.

        If it's a simple field, wraps it in a container that adds extra features.
        If it's a nested layer, creates a layer for it.
        If it's an intermediate layer, copies over the relevant fields and creates a new layer for
        it.
        """
        if not full_name:
            full_name = f"{self._full_name}.{name}"

        if is_fake:
            # Populate with all fields that are supposed to be inside of it
            field = {key: value for key, value in self._all_fields.items()
                     if key.startswith(full_name)}
        if isinstance(field, dict):
            if name.endswith('_tree'):
                name = name.replace('_tree', '')
                full_name = f'{self._full_name}.{name}'
            return JsonLayer(name, field, full_name=full_name, is_intermediate=is_fake)
        elif isinstance(field, list):
            # For whatever reason in list-type object it goes back to using the original parent name
            return [self._make_wrapped_field(name, field_part,
                                             full_name=self._full_name.split('.')[0])
                    for field_part in field]

        return LayerFieldsContainer(LayerField(name=name, value=field))
