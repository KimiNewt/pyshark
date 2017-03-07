import os
import binascii
import py
from pyshark.packet.common import Pickleable


class LayerField(object):
    """
    Holds all data about a field of a layer, both its actual value and its name and nice representation.
    """
    # Note: We use this object with slots and not just a dict because
    # it's much more memory-efficient (cuts about a third of the memory).
    __slots__ = ['name', 'field', 'proto', 'showname', 'raw_value', 'show', 'hide', 'pos', 'size', 'unmaskedvalue']

    def __init__(self, name=None, field=None, proto=None, showname=None, value=None, show=None, hide=None, pos=None, size=None, unmaskedvalue=None):
        self.name = name
        self.showname = showname
        self.raw_value = value
        self.show = show
        self.pos = pos
        self.size = size
        self.unmaskedvalue = unmaskedvalue
        self.field = field
        self.proto = proto

        if hide and hide == 'yes':
            self.hide = True
        else:
            self.hide = False

    def __repr__(self):
        return '<LayerField %s: %s>' % (self.name, self.get_default_value())

    def get_default_value(self):
        """
        Gets the best 'value' string this field has.
        """
        val = self.show
        if not val:
            val = self.raw_value
        if not val:
            val = self.showname
        return val

    @property
    def showname_value(self):
        """
        For fields which do not contain a normal value, we attempt to take their value from the showname.
        """
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ')[1]

    @property
    def showname_key(self):
        if self.showname and ': ' in self.showname:
            return self.showname.split(': ')[0]

    def __getstate__(self):
        ret = {}
        for slot in self.__slots__:
            ret[slot] = getattr(self, slot)
        return ret

    def __setstate__(self, data):
        for key, val in data.iteritems():
            setattr(self, key, val)

    @property
    def binary_value(self):
        """
        Returns the raw value of this field (as a binary string)
        """
        return binascii.unhexlify(self.raw_value)

    @property
    def int_value(self):
        """
        Returns the raw value of this field (as an integer).
        """
        return int(self.raw_value, 16)


class LayerFieldsContainer(str, Pickleable):
    """
    An object which contains one or more fields (of the same name).
    When accessing member, such as showname, raw_value, etc. the appropriate member of the main (first) field saved
    in this container will be shown.
    """

    def __new__(cls, main_field, *args, **kwargs):
        obj = str.__new__(cls, main_field.get_default_value(), *args, **kwargs)
        obj.fields = [main_field]
        return obj

    def add_field(self, field):
        self.fields.append(field)

    @property
    def main_field(self):
        return self.fields[0]

    @property
    def alternate_fields(self):
        """
        Return the alternate values of this field containers (non-main ones).
        """
        return self.fields[1:]

    @property
    def all_fields(self):
        """
        Returns all fields in a list, the main field followed by the alternate fields.
        """
        return self.fields

    def __getattr__(self, item):
        return getattr(self.main_field, item)


class Layer(Pickleable):
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
        for field in xml_obj.findall('./field'):
            field_obj = self.objectify(field)
            if field_obj.name in self._all_fields.keys():
                self._all_fields[field_obj.name].add_field(field_obj)
            else:
                self._all_fields[field_obj.name] = LayerFieldsContainer(field_obj)
        for field in xml_obj.findall('./proto'):
            field_obj = self.objectify(field)
            if field_obj.name in self._all_fields.keys():
                self._all_fields[field_obj.name].add_field(field_obj)
            else:
                self._all_fields[field_obj.name] = LayerFieldsContainer(field_obj)

    def __getattr__(self, item):
        val = self.get_field(item)
        if val is None:
            raise AttributeError()
        if self.raw_mode:
            return val.raw_value
        return val

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + self.field_names

    def objectify(self, obj):
        """
        Recursing method for copying nested fields from XML object
        """
        attributes = dict(obj.attrib)

        fields = [self.objectify(field) for field in obj.findall('./field')]
        if len(fields) == 1:
            subfield = fields[0]
        elif fields:
            subfield = fields
        else:
            subfield = None

        fields = [self.objectify(field) for field in obj.findall('./proto')]
        if len(fields) == 1:
            subproto = fields[0]
        elif fields:
            subproto = fields
        else:
            subproto = None

        fld_obj = LayerField(field=subfield, proto=subproto, **attributes)
        return fld_obj

    def get_field(self, name):
        """
        Gets the XML field object of the given name.
        """
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
    def all_fields(self):
        """
        Return all LayerFieldContainer items in Layer
        """
        return self._all_fields

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
        all_fields = self._all_fields.values()
        all_fields += sum([field.alternate_fields for field in all_fields], [])
        return all_fields

    def _get_all_field_lines(self):
        """
        Returns all lines that represent the fields of the layer (both their names and values).
        """
        for field in self._get_all_fields_with_alternates():
            if field.hide:
                continue
            if field.showname:
                field_repr = field.showname
            elif field.show:
                field_repr = field.show
            else:
                continue
            yield '\t' + field_repr + os.linesep

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
