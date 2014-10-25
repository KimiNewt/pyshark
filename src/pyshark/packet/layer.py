import os
import py


class LayerField(object):
    """
    Holds all data about a field of a layer, both its actual value and its name and nice representation.
    """
    # Note: We use this object with slots and not just a dict because
    # it's much more memory-efficient (cuts about a third of the memory).
    __slots__ = ['name', 'showname', 'value', 'show', 'hide', 'pos', 'size', 'unmaskedvalue']

    def __init__(self, name=None, showname=None, value=None, show=None, hide=None, pos=None, size=None, unmaskedvalue=None):
        self.name = name
        self.showname = showname
        self.value = value
        self.show = show
        self.pos = pos
        self.size = size
        self.unmaskedvalue = unmaskedvalue

        if hide and hide == 'yes':
            self.hide = True
        else:
            self.hide = False


class Layer(object):
    """
    An object representing a Packet layer.
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
            self._all_fields[attributes['name']] = LayerField(**attributes)

    def __getattr__(self, item):
        val = self.get_field_value(item, raw=self.raw_mode)
        if val is None:
            raise AttributeError()
        return val

    def __dir__(self):
        return dir(type(self)) + self.__dict__.keys() + self._field_names

    def get_field(self, name):
        """
        Gets the XML field object of the given name.
        """
        for field_name, field in self._all_fields.items():
            if self._sanitize_field_name(name) == self._sanitize_field_name(field_name):
                return field

    def get_raw_value(self, name):
        """
        Returns the raw value of a given field
        """
        return self.get_field_value(name, raw=True)

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
            return field.value

        val = field.show
        if not val:
            val = field.value
        if not val:
            val = field.showname
        return val

    @property
    def _field_prefix(self):
        """
        Prefix to field names in the XML.
        """
        if self.layer_name == 'geninfo':
            return ''
        return self.layer_name + '.'
        
    @property
    def _field_names(self):
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

    def _get_all_field_lines(self):
        """
        Returns all lines that represent the fields of the layer (both their names and values).
        """
        for field in self._all_fields.values():
            if field.hide:
                continue
            if field.showname:
                field_repr = field.showname
            elif field.show:
                field_repr = field.show
            else:
                continue
            yield '\t' + field_repr + os.linesep