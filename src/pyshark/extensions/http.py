from pyshark.extensions.base import LayerExtension


class HTTPExtension(LayerExtension):
    PROTOCOL = "HTTP"
    FOR_JSON = True

    @classmethod
    def get_request_info(cls, layer):
        from pyshark.packet.layer import JsonLayer

        request_field = [field for field in layer.field_names
                         if field.endswith("\\r\\n") and field != "\\r\\n"][0]
        return JsonLayer("REQUEST", layer.get_field(request_field, as_dict=True), full_name="http")

    @classmethod
    def get_repr(cls, layer):
        is_request = layer.has_field("request")
        return "REQUEST" if is_request else "RESPONSE"
