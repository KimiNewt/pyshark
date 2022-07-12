import binascii
import json

from pyshark import cache
from pyshark.tshark import tshark


_MAPPING_CACHE_NAME = "ek_field_mapping.json"


class FieldNotFound(Exception):
    pass


class ProtocolMappingNotInitialized(Exception):
    pass


class _EkFieldMapping:

    def __init__(self):
        self._protocol_to_mapping = {}

    def load_mapping(self, tshark_version, tshark_path=None):
        if self._protocol_to_mapping:
            return

        mapping_cache_file = cache.get_cache_dir(tshark_version).joinpath(_MAPPING_CACHE_NAME)
        if mapping_cache_file.exists():
            self._protocol_to_mapping = json.load(mapping_cache_file.open())
        else:
            self._protocol_to_mapping = tshark.get_ek_field_mapping(tshark_path=tshark_path)
            mapping_cache_file.open("w").write(json.dumps(self._protocol_to_mapping))

    def cast_field_value(self, protocol, field_name, field_value):
        """Casts the field value to its proper type according to the mapping"""
        if isinstance(field_value, list):
            return [self.cast_field_value(protocol, field_name, item) for item in field_value]
        if not isinstance(field_value, str):
            return field_value
        field_type = self.get_field_type(protocol, field_name)
        if field_type == str:
            return field_value
        if field_type == int and field_value.startswith("0x"):
            return int(field_value, 16)
        if field_type == bytes:
            try:
                return binascii.unhexlify(field_value.replace(":", ""))
            except binascii.Error:
                return field_value

        try:
            return field_type(field_value)
        except ValueError:
            return field_value

    def get_field_type(self, protocol, field_name):
        """Gets the Python type for the given field (only for EK fields).

        If we are unfamiliar with the type, str will be returned.
        """
        if not self._protocol_to_mapping:
            raise ProtocolMappingNotInitialized("Protocol mapping not initialized. Call load_mapping() first")
        if protocol not in self._protocol_to_mapping:
            raise FieldNotFound(f"Type mapping for protocol {protocol} not found")

        fields = self._protocol_to_mapping[protocol]["properties"]
        if field_name not in fields:
            return str
        return self._get_python_type_for_field_type(fields[field_name]["type"])

    def clear(self):
        self._protocol_to_mapping.clear()

    @classmethod
    def _get_python_type_for_field_type(cls, field_type):
        if field_type in ("integer", "long", "short"):
            return int
        if field_type == "float":
            return float
        if field_type == "date":
            # We don't use datetime.datetime because these can be timedeltas as well.
            # Better let the user decide.
            return float
        if field_type == "byte":
            return bytes
        # Other known types are IP. Retain as str
        return str


MAPPING = _EkFieldMapping()
