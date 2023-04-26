import datetime
import os
import binascii
import typing

from pyshark.packet import consts
from pyshark.packet.common import Pickleable
from pyshark.packet.layers.base import BaseLayer


class Packet(Pickleable):
    """A packet object which contains layers.

    Layers can be accessed via index or name.
    """

    def __init__(self, layers=None, frame_info=None, number=None,
                 length=None, captured_length=None, sniff_time=None, interface_captured=None):
        """
        Creates a Packet object with the given layers and info.

        :param layers: A list of BaseLayer objects.
        :param frame_info: Layer object for the entire packet frame (information like frame length, packet number, etc.
        :param length: Length of the actual packet.
        :param captured_length: The length of the packet that was actually captured (could be less then length)
        :param sniff_time: The time the packet was captured (timestamp)
        :param interface_captured: The interface the packet was captured in.
        """
        if layers is None:
            self.layers = []
        else:
            self.layers = layers
        self.frame_info = frame_info
        self.number = number
        self.interface_captured = interface_captured
        self.captured_length = captured_length
        self.length = length
        self.sniff_timestamp = sniff_time

    def __getitem__(self, item):
        """
        Gets a layer according to its index or its name

        :param item: layer index or name
        :return: BaseLayer object.
        """
        if isinstance(item, int):
            return self.layers[item]
        for layer in self.layers:
            if layer.layer_name.lower() == item.lower():
                return layer
        raise KeyError('Layer does not exist in packet')

    def __contains__(self, item):
        """Checks if the layer is inside the packet.

        :param item: name of the layer
        """
        try:
            self[item]
            return True
        except KeyError:
            return False

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + [l.layer_name for l in self.layers]

    def get_raw_packet(self) -> bytes:
        assert "FRAME_RAW" in self, "Packet contains no raw data. In order to contains it, " \
                                    "make sure that use_json and include_raw are set to True " \
                                    "in the Capture object"
        raw_packet = b''
        byte_values = [''.join(x) for x in zip(self.frame_raw.value[0::2], self.frame_raw.value[1::2])]
        for value in byte_values:
            raw_packet += binascii.unhexlify(value)
        return raw_packet

    def __len__(self):
        return int(self.length)

    def __bool__(self):
        return True

    @property
    def sniff_time(self) -> datetime.datetime:
        try:
            timestamp = float(self.sniff_timestamp)
        except ValueError:
            # If the value after the decimal point is negative, discard it
            # Google: wireshark fractional second
            timestamp = float(self.sniff_timestamp.split(".")[0])
        return datetime.datetime.fromtimestamp(timestamp)

    def __repr__(self):
        transport_protocol = ''
        if self.transport_layer != self.highest_layer and self.transport_layer is not None:
            transport_protocol = self.transport_layer + '/'

        return f'<{transport_protocol}{self.highest_layer} Packet>'

    def __str__(self):
        s = self._packet_string
        for layer in self.layers:
            s += str(layer)
        return s

    @property
    def _packet_string(self):
        """A simple pretty string that represents the packet."""
        return f'Packet (Length: {self.length}){os.linesep}'

    def pretty_print(self):
        for layer in self.layers:
            layer.pretty_print()
    # Alias
    show = pretty_print

    def __getattr__(self, item):
        """
        Allows layers to be retrieved via get attr. For instance: pkt.ip
        """
        for layer in self.layers:
            if layer.layer_name.lower() == item.lower():
                return layer
        raise AttributeError(f"No attribute named {item}")

    @property
    def highest_layer(self) -> BaseLayer:
        return self.layers[-1].layer_name.upper()

    @property
    def transport_layer(self) -> BaseLayer:
        for layer in consts.TRANSPORT_LAYERS:
            if layer in self:
                return layer

    def get_multiple_layers(self, layer_name) -> typing.List[BaseLayer]:
        """Returns a list of all the layers in the packet that are of the layer type (an incase-sensitive string).

        This is in order to retrieve layers which appear multiple times in the same packet (i.e. double VLAN)
        which cannot be retrieved by easier means.
        """
        return [layer for layer in self.layers if layer.layer_name.lower() == layer_name.lower()]
