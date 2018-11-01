from pyshark.extensions.base import LayerExtension


class SSLExtension(LayerExtension):
    PROTOCOL = "SSL"
    FOR_JSON = True

    @classmethod
    def get_extensions(cls, ssl_layer):
        extensions = {}
        if not ssl_layer.record.has_field("handshake"):
            return {}

        for field_name in ssl_layer.record.handshake.field_names:
            if field_name.startswith("Extension: "):
                extensions[
                    field_name.split(": ", 1)[1]] = ssl_layer.record.handshake.get(field_name)
        return extensions
