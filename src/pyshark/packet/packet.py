from __future__ import print_function

import datetime
import os

from pyshark.packet import consts
from pyshark.packet.common import Pickleable


class Packet(Pickleable):
    """
    A packet object which contains layers.
    Layers can be accessed via index or name.
    """

    def __init__(self, layers=None, frame_info=None, number=None,
                 length=None, captured_length=None, sniff_time=None, interface_captured=None):
        """
        Creates a Packet object with the given layers and info.

        :param layers: A list of Layer objects.
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
        :return: Layer object.
        """
        if isinstance(item, int):
            return self.layers[item]
        for layer in self.layers:
            if layer.layer_name == item.lower():
                return layer
        raise KeyError('Layer does not exist in packet')

    def __contains__(self, item):
        """
        Checks if the layer is inside the packet.

        :param item: name of the layer
        """
        try:
            self[item]
            return True
        except KeyError:
            return False

    def __dir__(self):
        return dir(type(self)) + list(self.__dict__.keys()) + [l.layer_name for l in self.layers]

    @property
    def sniff_time(self):
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

        return '<%s%s Packet>' % (transport_protocol, self.highest_layer)

    def __str__(self):
        s = self._packet_string
        for layer in self.layers:
            s += str(layer)
        return s

    @property
    def _packet_string(self):
        """
        A simple pretty string that represents the packet.
        """
        return 'Packet (Length: %s)%s' %(self.length, os.linesep)

    def pretty_print(self):
        print('self._packet_string')
        for layer in self.layers:
            layer.pretty_print()

    def __getattr__(self, item):
        """
        Allows layers to be retrieved via get attr. For instance: pkt.ip
        """
        for layer in self.layers:
            if layer.layer_name == item:
                return layer
        raise AttributeError()

    @property
    def highest_layer(self):
        return self.layers[-1].layer_name.upper()

    @property
    def layer_names(self):
        """
        Returns all layer names
        """
        return [layer.layer_name for layer in self.layers]

    @property
    def all_layers(self):
        """
        Returns list of layers in packet
        """
        return self.layers

    @property
    def transport_layer(self):
        for layer in consts.TRANSPORT_LAYERS:
            if layer in self:
                return layer

    def get_multiple_layers(self, layer_name):
        """
        Returns a list of all the layers in the packet that are of the layer type (an incase-sensitive string).
        This is in order to retrieve layers which appear multiple times in the same packet (i.e. double VLAN) which cannot be
        retrieved by easier means.
        """
        return [layer for layer in self.layers if layer.layer_name.lower() == layer_name.lower()]
