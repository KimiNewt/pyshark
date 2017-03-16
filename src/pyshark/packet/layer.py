import operator
import os

import py

from pyshark.packet.common import Pickleable
from pyshark.packet.fields import LayerField, LayerFieldsContainer


class Layer(Pickleable):
    """
    An object reJpresenting a Packet layer.
    """
    DATA_LAYER = 'data'

    def __init__(self, xml_obj=None, raw_mode=False):
        self.raw_mode = raw_mode

        self._layer_name = xml_obj.attrib['name']
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

    def __getattr__(self, item):
        val = self.get_field(item)
        if val is None:
            raise AttributeError()
        if self.raw_mode:
            return val.raw_value
        return val

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + self.field_names

    def get_field(self, name):
        """
        Gets the XML field object of the given name.
        """
        # Quicker in case the exact name was used.
        field = self._all_fields.get(name)
        if field is not None:
            return field

        for field_name, field in self._all_fields.items():
            if self._sanitize_field_name(name) == self._sanitize_field_name(field_name):
                return field

    def get_field_value(self, name, raw=False):
        """
        Tries getting the value of the given field.
        Tries it in the following order: show (standard nice display), value (raw value), showname (extended nice display).

        :param name: The name of the field
        :param raw: Only return raw value
        :return: str of value
        """
        field = self.get_field(name)
        if field is None:
            return

        if raw:
            return field.raw_value

        return field

    @property
    def _field_prefix(self):
        """
        Prefix to field names in the XML.
        """
        if self.layer_name == 'geninfo':
            return ''
        return self.layer_name + '.'
        
    @property
    def field_names(self):
        """
        Gets all XML field names of this layer.
        :return: list of strings
        """
        return [self._sanitize_field_name(field_name)
                for field_name in self._all_fields]

    @property
    def layer_name(self):
        if self._layer_name == 'fake-field-wrapper':
            return self.DATA_LAYER
        return self._layer_name

    def _sanitize_field_name(self, field_name):
        """
        Sanitizes an XML field name (since it might have characters which would make it inaccessible as a python attribute).
        """
        field_name = field_name.replace(self._field_prefix, '')
        return field_name.replace('.', '_').replace('-', '_').lower()

    def __repr__(self):
        return '<%s Layer>' % self.layer_name.upper()

    def __str__(self):
        if self.layer_name == self.DATA_LAYER:
            return 'DATA'

        s = 'Layer %s:' % self.layer_name.upper() + os.linesep
        for field_line in self._get_all_field_lines():
            s += field_line
        return s

    def pretty_print(self):
        tw = py.io.TerminalWriter()
        if self.layer_name == self.DATA_LAYER:
            tw.write('DATA')
            return

        tw.write('Layer %s:' % self.layer_name.upper() + os.linesep, yellow=True, bold=True)
        for field_line in self._get_all_field_lines():
            if ':' in field_line:
                field_name, field_line = field_line.split(':', 1)
                tw.write(field_name + ':', green=True, bold=True)
            tw.write(field_line, bold=True)

    def _get_all_fields_with_alternates(self):
        all_fields = list(self._all_fields.values())
        all_fields += sum([field.alternate_fields for field in all_fields
                           if isinstance(field, LayerFieldsContainer)], [])
        return all_fields

    def _get_all_field_lines(self):
        """
        Returns all lines that represent the fields of the layer (both their names and values).
        """
        for field in self._get_all_fields_with_alternates():
            if isinstance(field, Layer):
                yield "\t" + field.layer_name + ":" + os.linesep
                for line in field._get_all_field_lines():
                    # Python2.7
                    yield "\t" + line
                continue

            field_repr = self._get_field_repr(field)
            if not field_repr:
                continue
            yield '\t' + field_repr + os.linesep

    def _get_field_repr(self, field):
        if field.hide:
            return
        if field.showname:
            return field.showname
        elif field.show:
            return field.show
        elif field.raw_value:
            return "%s: %s" % (self._sanitize_field_name(field.name), field.raw_value)

    def get_field_by_showname(self, showname):
        """
        Gets a field by its "showname"
        (the name that appears in Wireshark's detailed display i.e. in 'User-Agent: Mozilla...', 'User-Agent' is the
         showname)

         Returns None if not found.
        """
        for field in self._get_all_fields_with_alternates():
            if field.showname_key == showname:
                # Return it if "XXX: whatever == XXX"
                return field


class JsonLayer(Layer):
    raw_mode = False

    def __init__(self, layer_name, layer_dict):
        """
        Creates a JsonLayer and under sublayers redursively.

        :param base_name: the name of the prefix for field keys (it isn't the layer name on subtrees)
        """
        self._layer_name = layer_name
        self._wrapped_fields = {}
        if not isinstance(layer_dict, dict):
            self.value = layer_dict
            self._all_fields = {}
            return

        self._all_fields = layer_dict

    def _sanitize_field_name(self, field_name):
        return field_name.rsplit('.', 1)[-1]

    def _get_all_fields_with_alternates(self):
        return [self.get_field(name) for name in self.field_names]

    def get_field(self, name):
        # We only make the wrappers here (lazily) to avoid creating a ton of objects needlessly.
        field = self._wrapped_fields.get(name)
        if field is None:
            field = super(JsonLayer, self).get_field(name)
            if isinstance(field, dict):
                field = JsonLayer(name, field)
            else:
                field = LayerFieldsContainer(LayerField(name=name, value=field))
            self._wrapped_fields[name] = field
        return field
