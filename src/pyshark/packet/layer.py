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

    def get(self, item, default=None):
        """
        Works the same way as getattr, but returns the given default if not the field was not found
        """
        try:
            return getattr(self, item)
        except AttributeError:
            return default

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
            # Change to yield from
            for line in self._get_field_or_layer_repr(field):
                yield line

    def _get_field_or_layer_repr(self, field):
        if isinstance(field, Layer):
            yield "\t" + field.layer_name + ":" + os.linesep
            for line in field._get_all_field_lines():
                # Python2.7 (no yield from)
                yield "\t" + line
        elif isinstance(field, list):
            for subfield_or_layer in field:
                for line in self._get_field_or_layer_repr(subfield_or_layer):
                    yield line
        else:
            field_repr = self._get_field_repr(field)
            if field_repr:
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

    def __init__(self, layer_name, layer_dict, full_name=None, is_intermediate=False):
        """Creates a JsonLayer. All sublayers and fields are created lazily later."""
        self._layer_name = layer_name
        self.duplicate_layers = []
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

    def _sanitize_field_name(self, field_name):
        return field_name.replace(self._full_name + '.', '')

    @property
    def field_names(self):
        return list(set([self._sanitize_field_name(name) for name in self._all_fields
                         if name.startswith(self._full_name)] +
                        [name.rsplit('.', 1)[1] for name in self._all_fields if '.' in name]))

    def _get_all_fields_with_alternates(self):
        return [self.get_field(name) for name in self.field_names]

    def get_field(self, name):
        """Gets a field by its full or partial name."""
        # We only make the wrappers here (lazily) to avoid creating a ton of objects needlessly.
        field = self._wrapped_fields.get(name)
        if field is None:
            is_fake = False
            field = self._get_internal_field_by_name(name)
            if field is None:
                # Might be a "fake" field in JSON
                is_fake = self._is_fake_field(name)
                if not is_fake:
                    raise AttributeError("No such field %s" % name)
            field = self._make_wrapped_field(name, field, is_fake=is_fake)
            self._wrapped_fields[name] = field
        return field

    def _get_internal_field_by_name(self, name):
        """Gets the field by name, or None if not found."""
        field = self._all_fields.get(name, self._all_fields.get('%s.%s' % (self._full_name, name)))
        if field is not None:
            return field
        for field_name in self._all_fields:
            # Specific name
            if field_name.endswith('.%s' % name):
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
        field_full_name = '%s.%s.' % (self._full_name, name)
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
            full_name = '%s.%s' % (self._full_name, name)

        if is_fake:
            # Populate with all fields that are supposed to be inside of it
            field = {key: value for key, value in self._all_fields.items()
                     if key.startswith(full_name)}
        if isinstance(field, dict):
            if name.endswith('_tree'):
                name = name.replace('_tree', '')
                full_name = '%s.%s' % (self._full_name, name)
            return JsonLayer(name, field, full_name=full_name, is_intermediate=is_fake)
        elif isinstance(field, list):
            # For whatever reason in list-type object it goes back to using the original parent name
            return [self._make_wrapped_field(name, field_part,
                                             full_name=self._full_name.split('.')[0])
                    for field_part in field]

        return LayerFieldsContainer(LayerField(name=name, value=field))

    def has_field(self, dotted_name):
        """
        Checks whether the layer has the given field name.
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

