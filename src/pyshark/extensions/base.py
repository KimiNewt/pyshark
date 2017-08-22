class LayerExtension(object):
    """Extensions which can supply extra methods for layers.

    To implement, override one of the given methods or create a new one that receives the layer.
    """
    # Wrapped protocol
    PROTOCOL = None
    FOR_JSON = False

    @classmethod
    def fits_layer(cls, layer):
        from pyshark.packet.layer import JsonLayer, Layer
        kls = JsonLayer if cls.FOR_JSON else Layer
        if cls.PROTOCOL.lower() == layer.layer_name.lower() and layer.__class__ == kls:
            return True
        return False

    @classmethod
    def get_repr(cls, layer):
        """Extra info which will appear in the packet repr if the layer is the highest layer"""
        return ""
