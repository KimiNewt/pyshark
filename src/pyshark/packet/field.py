import os
from lxml import objectify

def get_attrib(xml_obj,attr):
	if attr in xml_obj.attrib:
		return 	xml_obj.attrib[attr]
	else:
		return None


class Field(object):
    """
    A object Representing A Field and Has all his subfields too
    """
    DATA_LAYER = 'data'

    def __init__(self, xml_obj=None,depth=0):
	
	self.attr = {}	
	self.attr['name']=get_attrib(xml_obj,'name')
        self.attr['showname'] = get_attrib(xml_obj,'showname')
        self.attr['value'] = get_attrib(xml_obj,'value')
        self.attr['show'] = get_attrib(xml_obj,'show')
        self.attr['pos'] = get_attrib(xml_obj,'pos')
        self.attr['size'] = get_attrib(xml_obj,'size')
	self.attr['value'] = get_attrib(xml_obj,'value')
        self.attr['unmaskedvalue'] = get_attrib(xml_obj,'unmaskedvalue')
	self.fields = []
	self.depth=depth
	if get_attrib(xml_obj,'hide') == "yes":
		self.attr['hide']=True
	else:
		self.attr['hide']=False
	if hasattr(xml_obj,"field"):
		for SubField in xml_obj["field"]:
			self.fields.append(Field(SubField,depth+1))

    def __getitem__(self,name):
	for field in self.fields:
		if field.layer_name == name:
			return field
	return None


    def get_SubField(self, name,SearchByAttrib='name'):
        """
        Find a SubField of the Field. look by the Attribute given in SearchByAttrib.

        :param name: The name of the field
        :param SearchByAttrib: The Attribute to look by.
        :return: Field
        """
        for field in self.fields:
		if field.attr[SearchByAttrib] == name:
			return field
	return None

    def get_field_value(self,raw=False):
        """
        Tries getting the value of the given field.
        Tries it in the following order: show (standard nice display), value (raw value), showname (extended nice display).

        :param raw: Only return raw value
        :return: str of value
        """

        if raw:
            return self.get_Attr('value')

        val = self.get_Attr('show')
        if not val:
            val = self.get_Attr('value')
        if not val:
            val = field.self.get_Attr('showname')
        return val


    def get_Attr(self,name):
	if name in self.attr:
		return self.attr[name]
	else:
		return None
    @property
    def layer_name(self):
	return self._sanitize_field_name(self.get_Attr('name'))

    def __repr__(self):
        return '<%s Field>' % self.get_Attr('name')

    def __dir__(self):
        return dir(type(self)) + self.__dict__.keys() + [l.layer_name for l in self.fields]

    def __str__(self):
	if self.layer_name == self.DATA_LAYER:
            return 'DATA'

	s=""
	if self.get_Attr('hide') == False:
	    field_repr = None
            if self.get_Attr('showname'):
                field_repr = self.get_Attr('showname')
            elif self.get_Attr('show'):
                field_repr = self.get_Attr('show')
            if 	field_repr:
            	s += self.depth*'\t' + field_repr + os.linesep	
		
	for field in self.fields:
	    s+= str(field)
	return s

    def __contains__(self, item):
        """
        Checks if the Field is inside the Filed.

        :param item: name of the Field
        """
        try:
            self[item]
            return True
        except KeyError:
            return False

    def __getattr__(self, item):
        """
        Allows Field to be retrieved via get attr. For instance: ip.src
        """
        for layer in self.fields:
            if layer.layer_name == item:
                return layer
        raise AttributeError()

    def _sanitize_field_name(self, field_name):
        """
        Sanitizes an XML field name (since it might have characters which would make it inaccessible as a python attribute).
        """
        return field_name.replace('.', '_')
		

    


