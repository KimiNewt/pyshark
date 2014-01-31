import os


class Layer(object):
    """
    An object representing a Packet layer.
    """
    DATA_LAYER = 'data'

    def __init__(self, xml_obj=None, raw_mode=False):
        self.xml_obj = xml_obj
        self.raw_mode = raw_mode

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
        for field in self._all_fields:
            if name == self._sanitize_field_name(field.attrib['name']):
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
            return field.attrib.get('value', None)

        val = field.attrib.get('show', None)
        if not val:
            val = field.attrib.get('value', None)
        if not val:
            val = field.attrib.get('showname', None)
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
    def _all_fields(self):
        return self.xml_obj.findall('.//field')

    @property
    def _field_names(self):
        """
        Gets all XML field names of this layer.
        :return: list of strings
        """
        return [self._sanitize_field_name(field.attrib['name'])
                for field in self._all_fields]

    @property
    def layer_name(self):
        name = self.xml_obj.attrib['name']
        if name == 'fake-field-wrapper':
            return self.DATA_LAYER
        return name

    def _sanitize_field_name(self, field_name):
        """
        Sanitizes an XML field name (since it might have characters which would make it inaccessible as a python attribute).
        """
        field_name = field_name.replace(self._field_prefix, '')
        return field_name.replace('.', '_')

    def __repr__(self):
        return '<%s Layer>' %(self.layer_name.upper())

    def __str__(self):
        if self.layer_name == self.DATA_LAYER:
            return 'DATA'

        s = 'Layer %s:' % self.layer_name.upper() + os.linesep
        for field in self._all_fields:
            if 'hide' in field.attrib and field.attrib['hide']:
                continue
            if 'showname' in field.attrib:
                field_repr = field.attrib['showname']
            elif 'show' in field.attrib:
                field_repr = field.attrib['show']
            else:
                continue
            s += '\t' + field_repr + os.linesep
        return s