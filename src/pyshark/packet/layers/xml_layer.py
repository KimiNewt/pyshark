import os
import typing
import io

from pyshark.packet.common import colored
from pyshark.packet.fields import LayerField, LayerFieldsContainer
from pyshark.packet.layers import base


class XmlLayer(base.BaseLayer):
    __slots__ = [
        "raw_mode",
        "_all_fields"
    ] + base.BaseLayer.__slots__

    def __init__(self, xml_obj=None, raw_mode=False):
        super().__init__(xml_obj.attrib['name'])
        self.raw_mode = raw_mode

        self._all_fields = {}

        # We copy over all the fields from the XML object
        # Note: we don't read lazily from the XML because the lxml objects are very memory-inefficient
        # so we'd rather not save them.
        for field in xml_obj.findall('.//field'):
            attributes = dict(field.attrib)
            field_obj = LayerField(**attributes)
            if attributes['name'] in self._all_fields:
                # Field name already exists, add this field to the container.
                self._all_fields[attributes['name']].add_field(field_obj)
            else:
                self._all_fields[attributes['name']] = LayerFieldsContainer(field_obj)

    def get_field(self, name) -> typing.Union[LayerFieldsContainer, None]:
        """Gets the XML field object of the given name."""
        # Quicker in case the exact name was used.
        field = self._all_fields.get(name)
        if field is not None:
            return field

        for field_name, field in self._all_fields.items():
            if self._sanitize_field_name(name) == self._sanitize_field_name(field_name):
                return field
        return None

    def get_field_value(self, name, raw=False) -> typing.Union[LayerFieldsContainer, None]:
        """Tries getting the value of the given field.

        Tries it in the following order: show (standard nice display), value (raw value),
        showname (extended nice display).

        :param name: The name of the field
        :param raw: Only return raw value
        :return: str of value
        """
        field = self.get_field(name)
        if field is None:
            return None

        if raw:
            return field.raw_value

        return field

    @property
    def field_names(self) -> typing.List[str]:
        """Gets all XML field names of this layer."""
        return [self._sanitize_field_name(field_name) for field_name in self._all_fields]

    @property
    def layer_name(self):
        if self._layer_name == 'fake-field-wrapper':
            return base.DATA_LAYER_NAME
        return super().layer_name

    def __getattr__(self, item):
        val = self.get_field(item)
        if val is None:
            raise AttributeError()
        if self.raw_mode:
            return val.raw_value
        return val

    @property
    def _field_prefix(self) -> str:
        """Prefix to field names in the XML."""
        if self.layer_name == 'geninfo':
            return ''
        return self.layer_name + '.'

    def _sanitize_field_name(self, field_name):
        """Sanitizes an XML field name

        An xml field might have characters which would make it inaccessible as a python attribute).
        """
        field_name = field_name.replace(self._field_prefix, '')
        return field_name.replace('.', '_').replace('-', '_').lower()

    def _pretty_print_layer_fields(self, file: io.IOBase):
        for field_line in self._get_all_field_lines():
            if ':' in field_line:
                field_name, field_line = field_line.split(':', 1)
                file.write(colored(field_name + ':', "green", attrs=["bold"]))
            file.write(colored(field_line, attrs=["bold"]))

    def _get_all_fields_with_alternates(self):
        all_fields = list(self._all_fields.values())
        all_fields += sum([field.alternate_fields for field in all_fields
                           if isinstance(field, LayerFieldsContainer)], [])
        return all_fields

    def _get_all_field_lines(self):
        """Returns all lines that represent the fields of the layer (both their names and values)."""
        for field in self._get_all_fields_with_alternates():
            yield from self._get_field_or_layer_repr(field)

    def _get_field_or_layer_repr(self, field):
        field_repr = self._get_field_repr(field)
        if field_repr:
            yield f"\t{field_repr}{os.linesep}"

    def _get_field_repr(self, field):
        if field.hide:
            return
        if field.showname:
            return field.showname
        elif field.show:
            return field.show
        elif field.raw_value:
            return f"{self._sanitize_field_name(field.name)}: {field.raw_value}"

    def get_field_by_showname(self, showname) -> typing.Union[LayerFieldsContainer, None]:
        """Gets a field by its "showname"
        This is the name that appears in Wireshark's detailed display i.e. in 'User-Agent: Mozilla...',
        'User-Agent' is the .showname
        Returns None if not found.
        """
        for field in self._get_all_fields_with_alternates():
            if field.showname_key == showname:
                # Return it if "XXX: whatever == XXX"
                return field
        return None
